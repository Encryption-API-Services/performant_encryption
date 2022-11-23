use std::ffi::{CString, c_char};

use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};

#[no_mangle] 
pub extern "C" fn get_private_key(key_size: usize) -> *mut c_char {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
    return CString::new(private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()).unwrap().into_raw();
}