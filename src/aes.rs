use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::ffi::{c_char, CStr, CString};

#[no_mangle]
pub extern "C" fn aes256_encrypt_string(
    key: *const c_char,
    to_encrypt: *const c_char,
) -> *mut c_char {
    let string_key = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();

    let string_to_encrypt: &str = unsafe {
        assert!(!to_encrypt.is_null());

        CStr::from_ptr(to_encrypt)
    }
    .to_str()
    .unwrap();

    let mc: magic_crypt::MagicCrypt256 = new_magic_crypt!(string_key, 256);
    let base64_string: CString = CString::new(mc.encrypt_str_to_base64(string_to_encrypt)).unwrap();
    return base64_string.into_raw();
}

#[test]
fn aes_encrypt_string_test() {
    let key = "aesKey";
    let key_cstr = CString::new(key).unwrap();
    let key_bytes = key_cstr.as_bytes_with_nul();
    let key_ptr = key_bytes.as_ptr() as *const i8;

    let to_encrypt = "TestStringToEncrypt";
    let to_encrypt_cstr = CString::new(to_encrypt).unwrap();
    let to_encrypt_bytes = to_encrypt_cstr.as_bytes_with_nul();
    let to_encrypt_ptr = to_encrypt_bytes.as_ptr() as *const i8;

    let encrypted_string_ptr = aes256_encrypt_string(key_ptr, to_encrypt_ptr);
    let encrypted_string_cstr = unsafe { CString::from_raw(encrypted_string_ptr) };
    let encrypted_string = encrypted_string_cstr.to_str().unwrap();
    assert_ne!(encrypted_string, to_encrypt);
    assert_ne!(encrypted_string, key);
}

#[no_mangle]
pub extern "C" fn aes256_decrypt_string(
    key: *const c_char,
    to_decrypt: *const c_char,
) -> *mut c_char {
    let string_key = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();

    let string_to_decrypt: &str = unsafe {
        assert!(!to_decrypt.is_null());

        CStr::from_ptr(to_decrypt)
    }
    .to_str()
    .unwrap();

    let mc: magic_crypt::MagicCrypt256 = new_magic_crypt!(string_key, 256);
    let decrypted_string =
        CString::new(mc.decrypt_base64_to_string(string_to_decrypt).unwrap()).unwrap();
    return decrypted_string.into_raw();
}

#[test]
fn aes256_decrypt_string_test() {
    let key = "aesKey";
    let key_cstr = CString::new(key).unwrap();
    let key_bytes = key_cstr.as_bytes_with_nul();
    let key_ptr = key_bytes.as_ptr() as *const i8;

    let to_encrypt = "TestStringToEncrypt";
    let to_encrypt_cstr = CString::new(to_encrypt).unwrap();
    let to_encrypt_bytes = to_encrypt_cstr.as_bytes_with_nul();
    let to_encrypt_ptr = to_encrypt_bytes.as_ptr() as *const i8;

    let encrypted_string_ptr = aes256_encrypt_string(key_ptr, to_encrypt_ptr);
    let encrypted_string_cstr = unsafe { CString::from_raw(encrypted_string_ptr) };
    let encrypted_string_bytes = encrypted_string_cstr.as_bytes_with_nul();
    let encrypted_string_ptr = encrypted_string_bytes.as_ptr() as *const i8;

    let decrypted_string_ptr = aes256_decrypt_string(key_ptr, encrypted_string_ptr);
    let decrypted_string_cstr = unsafe { CString::from_raw(decrypted_string_ptr) };
    let decrypted_string = decrypted_string_cstr.into_string().unwrap();
    assert_eq!(decrypted_string, to_encrypt);
}
