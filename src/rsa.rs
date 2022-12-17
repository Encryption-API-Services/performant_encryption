use std::{ffi::{CString, c_char}};

use magic_crypt::generic_array::typenum::assert_type;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey, pkcs1::EncodeRsaPublicKey};

#[repr(C)]
pub struct RsaKeyPair {
    pub pub_key: *mut c_char,
    pub priv_key: *mut c_char
}

#[no_mangle]
pub extern "C" fn get_key_pair(key_size: usize) -> RsaKeyPair {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let key_pair = RsaKeyPair {
        pub_key: CString::new(public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap().to_string()).unwrap().into_raw(),
        priv_key: CString::new(private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()).unwrap().into_raw()
    };
    return key_pair;
}

#[test]
fn get_key_pair_test() {
    let key_pair = get_key_pair(4096);

    let pub_key_cstr = unsafe {CString::from_raw(key_pair.pub_key)};
    let priv_key_cstr = unsafe {CString::from_raw(key_pair.priv_key)};

    let pub_key_str = pub_key_cstr.to_str().unwrap();
    let priv_key_str = priv_key_cstr.to_str().unwrap();


    assert_ne!(pub_key_str, priv_key_str);

}