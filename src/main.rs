mod nt_http;
mod resolve2;
mod types;
mod utils;
use crate::resolve2::{get_proc_by_hash, hash_str};
use crate::utils::get_module_by_hash;
// ────────────────────────────────────────────────────────────────
// Exemple d'utilisation (désactivé en prod)
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    #[test]
    fn test_http_get() {
        unsafe {
            let resp = crate::nt_http::http_get("example.com", "/").expect("requête échouée");
            assert_eq!(resp.status, 200);
        }
    }

    #[test]
    fn test_https_get() {
        unsafe {
            let resp = crate::nt_http::https_get("example.com", "/").expect("requête TLS échouée");
            assert_eq!(resp.status, 200);
            assert!(!resp.body.is_empty());
        }
    }
}

fn main() {
    unsafe {
        let ntdll = get_module_by_hash(hash_str("ntdll.dll"));
        println!("ntdll = {:?}", ntdll);

        let kernel32 = get_module_by_hash(hash_str("kernel32.dll"));
        println!("kernel32 = {:?}", kernel32);

        if let Some(k32) = kernel32 {
            let load_lib = get_proc_by_hash(k32, hash_str("LoadLibraryA"));
            println!("LoadLibraryA = {:?}", load_lib);
        }

        println!("Test resolve_host...");
        match crate::nt_http::resolve_host("example.com") {
            None => println!("ECHEC: resolve_host"),
            Some(ip) => {
                println!("OK: ip = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

                println!("Test HTTP...");
                match crate::nt_http::nt_request(ip, 80, "GET", "example.com", "/", &[], &[], false)
                {
                    None => println!("ECHEC: HTTP"),
                    Some(r) => println!("OK: HTTP status={}", r.status),
                }

                println!("Test HTTPS...");
                match crate::nt_http::nt_request(ip, 443, "GET", "example.com", "/", &[], &[], true)
                {
                    None => println!("ECHEC: HTTPS"),
                    Some(r) => println!("OK: HTTPS status={}", r.status),
                }
            }
        }
    }
}
