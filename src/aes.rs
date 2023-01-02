use aes_gcm::{Aes256Gcm, aead::{OsRng, AeadMut}, Nonce, KeyInit};
use std::ffi::{c_char, CStr, CString};

#[repr(C)]
pub struct AesEncrypt {
    pub key: *mut c_char,
    pub ciphertext: *mut c_char,
}

#[no_mangle]
pub extern "C" fn aes256_encrypt_string(
    nonce_key: *const c_char,
    to_encrypt: *const c_char,
) -> AesEncrypt {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());

        CStr::from_ptr(nonce_key)
    }.to_str().unwrap().as_bytes();

    let string_to_encrypt = unsafe {
        assert!(!to_encrypt.is_null());

        CStr::from_ptr(to_encrypt)
    }.to_str().unwrap().as_bytes();

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_string_key); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, string_to_encrypt.as_ref()).unwrap();
    return AesEncrypt {
        key: CString::new(base64::encode(key)).unwrap().into_raw(),
        ciphertext : CString::new(base64::encode(ciphertext)).unwrap().into_raw()
    }
}


#[no_mangle]
pub extern "C" fn aes256_decrypt_string(
    nonce_key: *const c_char,
    key: *const c_char,
    to_decrypt: *const c_char,
) -> *mut c_char {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());

        CStr::from_ptr(nonce_key)
    }.to_str().unwrap().as_bytes();

    let key_vec = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }.to_str().unwrap();

    let string_to_decrypt = unsafe {
        assert!(!to_decrypt.is_null());

        CStr::from_ptr(to_decrypt)
    }
    .to_str()
    .unwrap();

    let key_string = base64::decode(key_vec).unwrap();
    let string_to_decrypt_vec = base64::decode(string_to_decrypt).unwrap();

    let mut cipher = Aes256Gcm::new_from_slice(&key_string).unwrap();
    let nonce = Nonce::from_slice(&nonce_string_key);
    let plaintext = cipher.decrypt(nonce, string_to_decrypt_vec.as_ref()).unwrap();
    return CString::new(plaintext).unwrap().into_raw();
}
