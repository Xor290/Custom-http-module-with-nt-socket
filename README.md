# NT Sockets & Custom HTTP — Documentation technique


## Vue d'ensemble

Ce projet implémente des requêtes HTTP et HTTPS **sans appeler une seule fonction Win32 haut niveau**
(pas de `socket()`, `connect()`, `send()`, `recv()`, `WinHttpOpen()`…).

Tout repose sur trois couches basses :

```mermaid
graph TD
    A[Application Rust] --> B[NtDeviceIoControlFile\nsyscall NT]
    B --> C[\Device\Afd\nafd.sys]
    C --> D[\Device\Tcp\ntcpip.sys]
    D --> E[Réseau]

    style A fill:#4a4a8a,color:#fff
    style B fill:#2d6a4f,color:#fff
    style C fill:#1b4332,color:#fff
    style D fill:#1b4332,color:#fff
    style E fill:#555,color:#fff
```

---

## 1. Résolution des fonctions — PEB walk + FNV-1a

### Problème

On ne peut pas appeler `GetProcAddress` ou `LoadLibraryA` directement (ce sont déjà des fonctions Win32
qu'on cherche à éviter au démarrage). Au lancement, seul `ntdll.dll` est garanti chargé.

### Solution : PEB walk

Le **Process Environment Block** (PEB), accessible via `gs:[0x60]` sur x64, contient une liste chaînée
de tous les modules chargés dans le processus.

```mermaid
graph LR
    GS["gs:[0x60]"] --> PEB
    PEB -->|"+0x18"| LDR["PEB_LDR_DATA"]
    LDR -->|"+0x20"| LIST["InMemoryOrderModuleList\nliste circulaire"]
    LIST --> E1["LDR_DATA_TABLE_ENTRY\n+0x30 DllBase\n+0x58 Name.Length\n+0x60 Name.Buffer UTF-16"]
    E1 -->|flink| E2["LDR_DATA_TABLE_ENTRY\n..."]
    E2 -->|flink| E1

    style GS fill:#7b2d8b,color:#fff
    style PEB fill:#4a4a8a,color:#fff
    style LDR fill:#2d6a4f,color:#fff
    style LIST fill:#1b4332,color:#fff
```

On parcourt cette liste et on compare le nom de chaque DLL à un **hash FNV-1a 32 bits** calculé
à la compilation. Zéro chaîne en dur, zéro import visible.

### Hash FNV-1a

```rust
pub const fn hash_str(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 0x811c9dc5;   // offset_basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);  // FNV prime
        i += 1;
    }
    hash
}
```

Pour les noms de DLL (UTF-16 dans le PEB), `hash_utf16_lower` normalise d'abord en minuscules.

### Résolution d'une fonction dans un module PE

```mermaid
flowchart TD
    A["get_proc_by_hash(module, target_hash)"] --> B["Lire e_lfanew à +0x3C\n→ NT Header"]
    B --> C{"magic == 0x020B ?"}
    C -->|PE64| D["export_dir_offset = 0x88"]
    C -->|PE32| E["export_dir_offset = 0x78"]
    D & E --> F["Lire export_rva + export_size\ndepuis DataDirectory[0]"]
    F --> G["Itérer les noms exportés\nhash_str(name) == target ?"]
    G -->|Non| G
    G -->|Oui| H["Lire ordinal → fn_rva"]
    H --> I{"fn_rva dans\n[export_rva, export_rva+size) ?"}
    I -->|Oui — forwarder| J["Retourner None\nl'appelant essaie une autre DLL"]
    I -->|Non — code réel| K["Retourner base + fn_rva"]

    style J fill:#8b2020,color:#fff
    style K fill:#2d6a4f,color:#fff
```

> **Exemple concret** : sur Windows 10/11, `schannel.dll!AcquireCredentialsHandleW` est un forwarder
> vers `sspicli.AcquireCredentialsHandleW`. Sans détection, on transmute la chaîne ASCII en pointeur
> de fonction et on crashe.

---

## 2. Création du socket NT — NtCreateFile + EA buffer

### Principe

```mermaid
graph LR
    WS["ws2_32!socket()"] -.->|wrapping| NT
    NT["NtCreateFile(\n  \\Device\\Afd\\Endpoint,\n  EA buffer\n)"] --> H["HANDLE = socket"]

    style WS fill:#555,color:#aaa,stroke-dasharray:5
    style NT fill:#2d6a4f,color:#fff
    style H fill:#4a4a8a,color:#fff
```

On l'appelle directement avec un **EA buffer** (Extended Attributes) qui décrit le type de socket.

### Format de l'EA buffer (76 octets)

```mermaid
block-beta
  columns 1
  block:header["FILE_FULL_EA_INFORMATION header (8 octets)"]
    a["[0..4] NextEntryOffset = 0"]
    b["[4] Flags = 0 | [5] EaNameLength = 15 | [6..8] EaValueLength = 52"]
  end
  block:name["EA Name (16 octets)"]
    c["[8..24] 'AfdOpenPacketXX\\0'"]
  end
  block:pkt["AFD_OPEN_PACKET (52 octets)"]
    d["[24..28] endpoint_flags = 0x100"]
    e["[28..32] group_id = 0"]
    f["[32..36] AF_INET = 2"]
    g["[36..40] SOCK_STREAM = 1"]
    h["[40..44] IPPROTO_TCP = 6"]
    i["[44..48] transport_name_length = 22"]
    j["[48..70] L'\\Device\\Tcp' (UTF-16)"]
    k["[70..76] padding = 0"]
  end
```

---

## 3. IOCTLs AFD

### Vue d'ensemble des opérations

```mermaid
sequenceDiagram
    participant App
    participant AFD as \Device\Afd (afd.sys)
    participant TCP as \Device\Tcp

    App->>AFD: NtCreateFile + EA buffer
    AFD-->>App: HANDLE socket

    App->>AFD: IOCTL_AFD_BIND (0x12003)
    AFD-->>App: STATUS_SUCCESS

    App->>AFD: IOCTL_AFD_CONNECT (0x12007) + event
    AFD->>TCP: SYN
    TCP-->>AFD: SYN-ACK
    AFD-->>App: STATUS_PENDING → NtWaitForSingleObject → OK

    App->>AFD: IOCTL_AFD_SEND (0x1201F) + data
    AFD->>TCP: données
    AFD-->>App: STATUS_SUCCESS

    App->>AFD: IOCTL_AFD_RECV (0x12017) + event
    TCP-->>AFD: réponse
    AFD-->>App: STATUS_PENDING → NtWaitForSingleObject → données
```

### Modèle asynchrone (event-based)

```mermaid
flowchart LR
    A["NtCreateEvent(event)"] --> B["NtDeviceIoControlFile(\n  handle, event, ...\n)"]
    B --> C{"status ?"}
    C -->|STATUS_PENDING\n0x103| D["NtWaitForSingleObject(event)"]
    C -->|STATUS_SUCCESS\n0x0| E["Lire isb.information"]
    D --> E
    E --> F["NtClose(event)"]

    style D fill:#2d6a4f,color:#fff
```

### Structures AFD sur x64 — padding obligatoire

```mermaid
block-beta
  columns 1
  block:wsabuf["AFD_WSABUF — 16 octets"]
    columns 4
    w1["len\nu32\n+0x00"]:1
    w2["_pad\nu32\n+0x04"]:1
    w3["buf_ptr\nu64\n+0x08"]:2
  end
  block:sendinfo["AFD_SEND_INFO / AFD_RECV_INFO — 24 octets ⚠️ (pas 20 !)"]
    columns 4
    s1["buf_array_ptr\nu64\n+0x00"]:2
    s2["buf_count\nu32\n+0x08"]:1
    s3["afd_flags\nu32\n+0x0C"]:1
    s4["tdi_flags\nu32\n+0x10\n(0x20 pour recv)"]:1
    s5["_pad\nu32\n+0x14"]:1
  end
```

> **Piège** : `InputBufferLength = 20` → `STATUS_INVALID_PARAMETER (0xC000000D)`. Il faut 24.
> Pour `IOCTL_AFD_RECV`, `tdi_flags` **doit** être `TDI_RECEIVE_NORMAL = 0x20`.

---

## 4. Résolution DNS — GetAddrInfoW via ws2_32

```mermaid
flowchart TD
    A["resolve_host(host)"] --> B{"IP directe ?\n'1.2.3.4'"}
    B -->|Oui| C["Parser les 4 octets\nretourner [u8;4]"]
    B -->|Non| D["get_module_by_hash(kernel32)\n→ LoadLibraryA"]
    D --> E["LoadLibraryA('ws2_32.dll')"]
    E --> F["get_proc_by_hash(ws2, WSAStartup)\nWSAStartup(0x0202)"]
    F --> G["get_proc_by_hash(ws2, GetAddrInfoW)\nGetAddrInfoW(hostname_utf16)"]
    G --> H{"AF_INET\ndans résultats ?"}
    H -->|Oui| I["SOCKADDR_IN +4 → [u8;4]\nFreeAddrInfoW"]
    H -->|Non| J["None"]

    style C fill:#2d6a4f,color:#fff
    style I fill:#2d6a4f,color:#fff
    style J fill:#8b2020,color:#fff
```

---

## 5. TLS via Schannel

### Résolution des fonctions SSPI — ordre de priorité

```mermaid
flowchart LR
    F["resolve_schannel_fn(hash)"] --> L["LoadLibrary:\nsspicli, secur32, schannel"]
    L --> T1["get_proc_by_hash\nsspicli.dll"]
    T1 -->|trouvé non-forwarder| OK["✓ adresse réelle"]
    T1 -->|None| T2["get_proc_by_hash\nsecur32.dll"]
    T2 -->|trouvé| OK
    T2 -->|None| T3["get_proc_by_hash\nschannel.dll"]
    T3 -->|trouvé non-forwarder| OK
    T3 -->|None| ERR["✗ None"]

    style OK fill:#2d6a4f,color:#fff
    style ERR fill:#8b2020,color:#fff
```

> Sur Win10/11, `sspicli.dll` contient les vraies implémentations.
> `schannel.dll` et `secur32.dll` redirigent via forwarders PE.

### SCHANNEL_CRED v4 — layout x64 (80 octets)

```mermaid
block-beta
  columns 2
  block:cred["SCHANNEL_CRED — 0x50 octets"]:2
    columns 4
    f1["+0x00\ndwVersion\n= 4"]:1
    f2["+0x04\ncCreds\n= 0"]:1
    f3["+0x08\npaCred ptr\n= NULL"]:2
    f4["+0x10\nhRootStore ptr\n= NULL"]:2
    f5["+0x18\ncMappers\n= 0"]:1
    f6["+0x1C\n_pad"]:1
    f7["+0x20\naphMappers ptr\n= NULL"]:2
    f8["+0x28\ncSupportedAlgs\n= 0"]:1
    f9["+0x2C\n_pad"]:1
    f10["+0x30\npalgSupportedAlgs ptr\n= NULL"]:2
    f11["+0x38\ngrbitEnabledProtocols\n= 0"]:1
    f12["+0x3C\ndwMinCipherStrength\n= 0"]:1
    f13["+0x40\ndwMaxCipherStrength\n= 0"]:1
    f14["+0x44\ndwSessionLifespan\n= 0"]:1
    f15["+0x48\ndwFlags\n= 0x1A"]:1
    f16["+0x4C\ndwCredFormat\n= 0"]:1
  end
```

`dwFlags = 0x08 (MANUAL_CRED_VALIDATION) | 0x02 (NO_DEFAULT_CREDS) | 0x10 (NO_SERVERNAME_CHECK)`

> Ne pas utiliser `dwVersion = 5` (SCH_CREDENTIALS) : layout différent, plus grand,
> champs intermédiaires manquants → hang silencieux dans `AcquireCredentialsHandleW`.

### Boucle de handshake TLS

```mermaid
sequenceDiagram
    participant App
    participant ISC as InitializeSecurityContext
    participant Srv as Serveur TLS

    App->>ISC: phCtx=NULL, pInput=NULL
    ISC-->>App: SEC_I_CONTINUE_NEEDED\n+ ClientHello dans out_sec
    App->>Srv: envoyer out_buf_data[..cb_buffer]

    Srv-->>App: ServerHello + Cert + ...
    App->>ISC: phCtx=&ctx, pInput=[TOKEN+EMPTY]
    alt record TLS incomplet
        ISC-->>App: SEC_E_INCOMPLETE_MSG
        App->>Srv: recv plus (sans vider recv_buf)
        App->>ISC: retry avec recv_buf étendu
    end
    ISC-->>App: SEC_I_CONTINUE_NEEDED\n+ Finished client
    App->>Srv: envoyer token

    Srv-->>App: Finished serveur
    App->>ISC: phCtx=&ctx, pInput=[TOKEN+EMPTY]
    ISC-->>App: SEC_E_OK ✓
```

**Règles critiques :**
- `pInput` : toujours **2 SecBuffer** — `SECBUFFER_TOKEN` + `SECBUFFER_EMPTY`. Avec un seul, ISC retourne `SEC_E_INVALID_TOKEN`.
- Ne **pas** utiliser `ISC_REQ_ALLOCATE_MEMORY` si tu envoies depuis ton propre buffer. Avec ce flag, Schannel alloue son buffer interne → `out_sec.pv_buffer` ≠ `out_buf_data` → tu envoies des zéros → le serveur répond par un TLS Alert → `SEC_E_INVALID_TOKEN`.
- `SECBUFFER_EXTRA (type=5)` en sortie d'ISC : octets non consommés à préserver pour la prochaine itération.

### Chiffrement / déchiffrement

```mermaid
block-beta
  columns 1
  block:enc["EncryptMessage — 4 SecBuffer"]
    columns 4
    e1["[0] STREAM_HEADER\ntype=7\n5 octets"]:1
    e2["[1] DATA\ntype=1\nplaintext"]:2
    e3["[2] STREAM_TRAILER\ntype=6\n64 octets"]:1
  end
  block:dec["DecryptMessage — 4 SecBuffer (entrée/sortie)"]
    columns 4
    d1["[0] DATA\ntype=1\ndonnées brutes\n→ plaintext après"]:2
    d2["[1..3] EMPTY\n→ EXTRA si\nbytes restants"]:2
  end
```

---

## 6. Flux HTTP/HTTPS complet

```mermaid
flowchart TD
    A["nt_request(ip, port, method, host, path, headers, body, use_tls)"] --> B["nt_create_socket()\nNtCreateFile + EA buffer"]
    B --> C["nt_tcp_connect()\nIOCTL_AFD_BIND\nIOCTL_AFD_CONNECT"]
    C --> D{"use_tls ?"}

    D -->|true| E["tls_handshake()\nAcquireCredentialsHandle\nboucle ISC"]
    D -->|false| F["build_request()\nHTTP/1.1 brut"]

    E --> G["build_request()"]
    G --> H["tls_send()\nEncryptMessage\n→ IOCTL_AFD_SEND"]
    H --> I["tls_recv() loop\nIOCTL_AFD_RECV\n→ DecryptMessage"]

    F --> J["IOCTL_AFD_SEND"]
    J --> K["IOCTL_AFD_RECV loop"]

    I & K --> L["parse_response()\ncherche \\r\\n\\r\\n\nextrait status"]
    L --> M["HttpResponse\n{ status, headers, body }"]

    style E fill:#2d6a4f,color:#fff
    style M fill:#4a4a8a,color:#fff
```

---

## 7. Tableau des codes d'erreur rencontrés

| Code NTSTATUS    | Nom                      | Cause fréquente dans ce code                                           |
|------------------|--------------------------|------------------------------------------------------------------------|
| `0xC000000D`     | STATUS_INVALID_PARAMETER | Buffer AFD 20 octets au lieu de 24 ; `tdi_flags=0` pour recv           |
| `0x00000103`     | STATUS_PENDING           | Normal — IOCTL async, attendre avec `NtWaitForSingleObject`            |
| `0x80090308`     | SEC_E_INVALID_TOKEN      | Envoi de zéros (piège `ISC_REQ_ALLOCATE_MEMORY`) ; 1 seul SecBuffer en entrée ISC |
| `0x80090318`     | SEC_E_INCOMPLETE_MSG     | Record TLS partiel — lire plus sans vider `recv_buf`                   |
| `0x00090312`     | SEC_I_CONTINUE_NEEDED    | Normal — handshake en cours, envoyer token et continuer                |

---

## 8. Utilisation du module

### API publique (`nt_http.rs`)

```mermaid
classDiagram
    class HttpResponse {
        +status: u16
        +headers: Vec~u8~
        +body: Vec~u8~
    }

    class nt_http {
        +resolve_host(host) Option~[u8;4]~
        +http_get(host, path) Option~HttpResponse~
        +https_get(host, path) Option~HttpResponse~
        +https_post_json(host, path, json) Option~HttpResponse~
        +nt_request(ip, port, method, host, path, headers, body, use_tls) Option~HttpResponse~
    }

    nt_http ..> HttpResponse : retourne
```

Toutes les fonctions sont `unsafe`.

### Exemples d'utilisation

#### GET HTTP simple

```rust
unsafe {
    match nt_http::http_get("example.com", "/") {
        Some(r) => println!("status={} body_len={}", r.status, r.body.len()),
        None    => println!("échec"),
    }
}
```

#### GET HTTPS

```rust
unsafe {
    match nt_http::https_get("example.com", "/") {
        Some(r) => {
            println!("status={}", r.status);
            println!("{}", String::from_utf8_lossy(&r.body));
        }
        None => println!("échec TLS"),
    }
}
```

#### POST JSON en HTTPS

```rust
unsafe {
    let payload = br#"{"key":"value"}"#;
    match nt_http::https_post_json("api.example.com", "/endpoint", payload) {
        Some(r) => println!("status={} body={:?}", r.status, r.body),
        None    => println!("échec"),
    }
}
```

#### Headers personnalisés (via `nt_request`)

```rust
unsafe {
    let ip = nt_http::resolve_host("api.example.com")?;
    let r = nt_http::nt_request(
        ip, 443, "POST", "api.example.com", "/upload",
        &[
            ("Authorization", "Bearer TOKEN"),
            ("Content-Type",  "application/octet-stream"),
        ],
        b"<binary data>",
        true,
    )?;
    println!("status={}", r.status);
}
```

#### IP directe (sans DNS)

```rust
unsafe {
    let ip = [1, 1, 1, 1];
    let r = nt_http::nt_request(ip, 80, "GET", "1.1.1.1", "/", &[], &[], false)?;
}
```

### Compilation

Ce projet cible **Windows x64** exclusivement. La compilation se fait depuis Linux/WSL via la toolchain `x86_64-pc-windows-gnu` :

```bash
# Debug
cargo build --target x86_64-pc-windows-gnu

# Release
cargo build --release --target x86_64-pc-windows-gnu

# Vérifier la compilation des tests sans les exécuter
cargo test --target x86_64-pc-windows-gnu --no-run
```

> Le binaire produit est un `.exe` dans `target/x86_64-pc-windows-gnu/debug/` ou `release/`.  
> Aucune dépendance externe — `[dependencies]` reste vide dans `Cargo.toml`.

### Intégrer dans un autre projet

1. Copier `src/nt_http.rs`, `src/resolve2.rs`, `src/types.rs`, `src/utils.rs`.
2. Déclarer les modules dans `main.rs` / `lib.rs` :
   ```rust
   mod nt_http;
   mod resolve2;
   mod types;
   mod utils;
   ```
3. Appeler depuis un bloc `unsafe` :
   ```rust
   use crate::nt_http;
   unsafe {
       let r = nt_http::https_get("example.com", "/").unwrap();
   }
   ```
4. Aucune dépendance externe — `Cargo.toml` reste vide.

### Limitations connues

| Limitation | Détail |
|------------|--------|
| IPv4 uniquement | `resolve_host` ne traite que `AF_INET`. IPv6 non supporté. |
| Pas de redirection | Les 301/302 ne sont pas suivis automatiquement. |
| Pas de chunked decoding | Le body est brut ; à décoder manuellement si `Transfer-Encoding: chunked`. |
| Recv partiel (HTTP) | `nt_recv_raw` s'arrête au premier chunk TCP. Peut manquer des données sur les grosses réponses. |
| Pas de vérif. certificat | `SCH_CRED_MANUAL_CRED_VALIDATION` activé. À implémenter via `QueryContextAttributesW(SECPKG_ATTR_REMOTE_CERT_CONTEXT)` si besoin. |

---

## 9. Guide d'utilisation

### Prérequis

| Prérequis | Détail |
|-----------|--------|
| **Rust** | Edition 2024 minimum (`edition = "2024"` dans `Cargo.toml`) |
| **Target Windows x64** | `rustup target add x86_64-pc-windows-gnu` |
| **Exécution** | Le binaire doit tourner sur **Windows x64** — pas de support Linux/macOS/ARM |
| **Pas de dépendances** | `[dependencies]` reste vide |

### Intégrer dans un projet existant

**Étape 1 — Copier les 4 fichiers source**

```
src/
  nt_http.rs    ← logique HTTP/HTTPS
  resolve2.rs   ← résolution PE + PEB walk
  types.rs      ← structures Windows
  utils.rs      ← helpers PEB / UTF-16
```

**Étape 2 — Déclarer les modules**

```rust
// main.rs ou lib.rs
mod nt_http;
mod resolve2;
mod types;
mod utils;
```

**Étape 3 — Appeler depuis un bloc `unsafe`**

```rust
use crate::nt_http;

fn main() {
    unsafe {
        let r = nt_http::http_get("example.com", "/").unwrap();
        println!("{}", r.status);
    }
}
```

---

### Choisir la bonne fonction

```mermaid
flowchart TD
    A["Faire une requête HTTP/HTTPS"] --> B{"Protocole ?"}
    B -->|HTTP port 80| C{"Besoin de\nheaders custom\nou body ?"}
    B -->|HTTPS port 443| D{"Besoin de\nheaders custom\nou body ?"}

    C -->|Non| E["http_get(host, path)"]
    C -->|Oui| F["nt_request(ip, 80, ...)"]

    D -->|GET simple| G["https_get(host, path)"]
    D -->|POST JSON| H["https_post_json(host, path, json)"]
    D -->|Autre| I["nt_request(ip, 443, ...)"]

    F --> J["resolve_host(host)\npour obtenir l'IP"]
    I --> J

    style E fill:#2d6a4f,color:#fff
    style G fill:#2d6a4f,color:#fff
    style H fill:#2d6a4f,color:#fff
    style F fill:#4a4a8a,color:#fff
    style I fill:#4a4a8a,color:#fff
```

---

### Gestion des erreurs

Toutes les fonctions retournent `Option<HttpResponse>` — `None` indique un échec réseau ou TLS, jamais une erreur HTTP (un 404 est un succès réseau).

```rust
unsafe {
    match nt_http::https_get("example.com", "/") {
        None => {
            // Échec : DNS, connexion TCP, handshake TLS
            // Pas de détail d'erreur exposé — vérifier les prints [DEBUG]
        }
        Some(r) if r.status != 200 => {
            // Connexion réussie, mais le serveur répond avec une erreur HTTP
            println!("HTTP {}", r.status);
        }
        Some(r) => {
            // Succès
            println!("{}", String::from_utf8_lossy(&r.body));
        }
    }
}
```

---

### Lire le body

**Texte (JSON, HTML…)**

```rust
let text = String::from_utf8_lossy(&r.body);
println!("{}", text);
```

**Binaire**

```rust
let bytes: &[u8] = &r.body;
std::fs::write("output.bin", bytes).unwrap();
```

**Lire un header précis**

Les headers sont dans `r.headers` (tout le bloc jusqu'à `\r\n\r\n`) :

```rust
let headers = String::from_utf8_lossy(&r.headers);
for line in headers.lines() {
    if line.to_lowercase().starts_with("content-type:") {
        println!("{}", line);
    }
}
```

> **Transfer-Encoding: chunked** — le body brut contient les tailles de chunks en hexadécimal.
> À décoder manuellement si le serveur utilise ce mode.

---

## 10. Pertinence en cyber offensive — Bypass AV/EDR

### Pourquoi les AV/EDR interceptent le réseau

Les solutions de sécurité modernes (EDR, AV, NDR) instrumentent le processus cible en **hookant les fonctions Win32 haut niveau** dans l'espace utilisateur. Elles injectent leurs DLL ou modifient les premiers octets (`jmp` hook) des fonctions exposées par `ws2_32.dll`, `winhttp.dll`, `wininet.dll` pour intercepter tout trafic réseau avant qu'il ne parte.

```mermaid
flowchart LR
    A["Programme\nnormal"] -->|appelle| B["ws2_32!connect()"]
    B -->|hook EDR| C["EDR DLL\nanalyse + log"]
    C -->|si autorisé| D["ntdll!NtDeviceIoControlFile\n(syscall réel)"]
    D --> E["Réseau"]

    A2["Ce module"] -->|appelle directement| D
    style C fill:#8b2020,color:#fff
    style A2 fill:#2d6a4f,color:#fff
```

Ce module **court-circuite entièrement la couche hookée** en appelant directement `NtDeviceIoControlFile` via `ntdll.dll`.

---

### Techniques de bypass utilisées

#### 1. PEB Walk — Résolution sans `GetProcAddress`

`GetProcAddress` et `LoadLibraryA` sont des fonctions Win32 fréquemment hookées ou surveillées. Les importer statiquement laisse des traces visibles dans l'**IAT** (Import Address Table) du binaire, analysée par tout scanner statique.

Ce module ne les importe jamais statiquement. Il résout les adresses en parcourant directement la liste des modules dans le PEB (`gs:[0x60]`), structure noyau inaccessible aux hooks user-land.

```mermaid
flowchart LR
    A["IAT du binaire\n(analysée par AV)"] -.->|"aucune entrée\nws2_32 / winhttp"| X["✗ rien à détecter"]
    B["gs:[0x60] PEB\n(kernel structure)"] -->|"PEB walk\n+ FNV-1a hash"| C["adresse de fonction\nrésolue au runtime"]

    style X fill:#2d6a4f,color:#fff
    style B fill:#4a4a8a,color:#fff
```

#### 2. Hash FNV-1a — Pas de chaînes en clair

Les noms de fonctions (`NtDeviceIoControlFile`, `AcquireCredentialsHandleW`…) n'apparaissent **jamais en clair** dans le binaire compilé. Seul leur hash 32 bits est présent. Les règles YARA et les scans de strings ne trouvent rien.

```
# Scan de strings naïf → rien
strings custom_http.exe | grep -i "NtDevice"  → (vide)
strings custom_http.exe | grep -i "connect"   → (vide)
```

#### 3. Direct Syscall via AFD — Bypass des hooks Winsock

Même si un EDR hook `ntdll!NtDeviceIoControlFile`, la surface d'attaque est réduite : un seul syscall générique pour toutes les opérations réseau, contre des dizaines de fonctions Winsock/WinHTTP chacune hookable individuellement.

Les solutions les plus avancées peuvent aussi déclencher les syscalls NT directement (syscall stub) pour éviter même le hook sur ntdll — ce module est structuré pour faciliter cette évolution.

#### 4. TLS natif via Schannel — Pas de librairie TLS tierce

Utiliser une librairie TLS embarquée (OpenSSL, mbedTLS…) est une signature statique forte. Ce module délègue le TLS à `schannel.dll` (composant Windows signé Microsoft), résolu dynamiquement par hash. Le trafic HTTPS produit est indiscernable d'un navigateur légitime.

#### 5. Pas d'import Win32 réseau — IAT propre

```mermaid
block-beta
  columns 2
  block:normal["Binaire classique\n(IAT visible)"]
    a["ws2_32.dll\n→ connect, send, recv"]
    b["winhttp.dll\n→ WinHttpOpen, ..."]
    c["crypt32.dll\n→ CertOpenStore, ..."]
  end
  block:ours["Ce module\n(IAT propre)"]
    d["ntdll.dll\n→ aucune fonction importée\nstatiquement"]
    e["(tout résolu\npar PEB walk)"]
  end

  style normal fill:#8b2020,color:#fff
  style ours fill:#2d6a4f,color:#fff
```

---

### Résumé des surfaces évitées

| Vecteur de détection | Binaire classique | Ce module |
|---|---|---|
| Imports IAT (`ws2_32`, `winhttp`) | Visibles | Absents |
| Strings en clair (noms de fonctions) | Visibles | Hachés FNV-1a |
| Hooks Winsock (EDR user-land) | Interceptés | Contournés |
| Hooks WinHTTP / WinInet | Interceptés | Non utilisés |
| Signature librairie TLS tierce | Possible | Absent (Schannel natif) |
| Appel `GetProcAddress` visible | Oui | Non |

---

## Disclaimer

> **Ce module est fourni à des fins strictement éducatives et de recherche en sécurité.**
>
> Les techniques décrites (PEB walk, résolution dynamique par hash, appels NT directs, bypass de hooks user-land) sont documentées publiquement dans la littérature académique et les conférences de sécurité (Black Hat, DEF CON, OffSec). Leur présentation ici vise à comprendre le fonctionnement interne de Windows et des mécanismes de défense.
>
> **L'utilisation de ce code sur des systèmes sans autorisation explicite et écrite du propriétaire est illégale** dans la plupart des juridictions (CFAA aux États-Unis, directive NIS2 en Europe, loi Godfrain en France…).
>
> L'auteur décline toute responsabilité quant à un usage malveillant, non autorisé ou illégal de ce code. Tout test doit être réalisé dans un environnement isolé, sur des systèmes vous appartenant ou dans le cadre d'un engagement de pentest contractuellement encadré.
