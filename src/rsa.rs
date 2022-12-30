use std::{ffi::{CString, c_char, CStr}, hash::Hash};

use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::{RsaPublicKey, pkcs8::{EncodePrivateKey, DecodePrivateKey}, pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey}, PublicKey, PaddingScheme};

#[repr(C)]
pub struct RsaKeyPair {
    pub pub_key: *mut c_char,
    pub priv_key: *mut c_char
}

pub struct RsaSignResult {
    pub signature: *mut c_char,
    pub public_key: *mut c_char
}

#[no_mangle]
pub extern "C" fn rsa_encrypt(pub_key: *const c_char, data_to_encrypt: *const c_char) -> *mut c_char {
    let pub_key_string = unsafe {
        assert!(!pub_key.is_null());

        CStr::from_ptr(pub_key)
    }.to_str().unwrap();

    let data_to_encrypt_bytes = unsafe {
        assert!(!data_to_encrypt.is_null());

        CStr::from_ptr(data_to_encrypt)
    }.to_str().unwrap().as_bytes();

    let public_key = RsaPublicKey::from_pkcs1_pem(pub_key_string).unwrap();
    let mut rng = rand::thread_rng();
    let encrypted_bytes = public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &data_to_encrypt_bytes).unwrap();
    return CString::new(base64::encode(encrypted_bytes)).unwrap().into_raw();
}

#[test]
fn rsa_encrypt_test() {
    let keys = get_key_pair(2048);
    let public_key_cstr = unsafe {CString::from_raw(keys.pub_key)};
    let public_key_ptr = public_key_cstr.as_bytes_with_nul().as_ptr() as *const c_char;

    let data_to_encrypt = "EncryptThisDataNow";
    let data_to_encrypt_ptr = CString::new(data_to_encrypt).unwrap().as_bytes_with_nul().as_ptr() as *const c_char;

    let encrypted = rsa_encrypt(public_key_ptr, data_to_encrypt_ptr);
    let encrypted_cstr = unsafe{CString::from_raw(encrypted)};
    let encrypted_str = encrypted_cstr.to_str().unwrap();
    assert_ne!(data_to_encrypt, encrypted_str);
}

#[no_mangle]
pub extern "C" fn rsa_decrypt(priv_key: *const c_char, data_to_decrypt: *const c_char) -> *mut c_char {
    let priv_key_string = unsafe {
        assert!(!priv_key.is_null());

        CStr::from_ptr(priv_key)
    }.to_str().unwrap();

    let data_to_decrypt_string = unsafe {
        assert!(!data_to_decrypt.is_null());
        CStr::from_ptr(data_to_decrypt)
    }.to_str().unwrap();

    let data_to_decrypt_bytes = base64::decode(data_to_decrypt_string).unwrap();

    let private_key = RsaPrivateKey::from_pkcs8_pem(priv_key_string).unwrap();
    let decrypted_bytes = private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &data_to_decrypt_bytes).expect("failed to decrypt");
    return CString::new(decrypted_bytes).unwrap().into_raw()
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
fn rsa_sign_nonffi_test() {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, 2094).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let data = b"testing";
    let signature = private_key.sign(PaddingScheme::new_pkcs1v15_sign_raw(), data).unwrap();
    assert_ne!(data.as_slice(), signature);
}

#[test]
fn rsa_verify_nonffi_test() {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, 2094).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let data =  "testing".as_bytes();
    let signature = private_key.sign(PaddingScheme::new_pkcs1v15_sign_raw(), data).unwrap();
    let verified = public_key.verify(PaddingScheme::new_pkcs1v15_sign_raw(), &data, &signature);
    assert_eq!(verified.is_err(), false);
}

#[test]
fn get_key_pair_test() {
    let key_size = 4096 as usize;
    let key_pair = get_key_pair(key_size);
    assert!(!key_pair.pub_key.is_null());
    assert!(!key_pair.priv_key.is_null());
}