use std::{ffi::{c_char, CStr, CString}};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};


#[no_mangle]
pub extern "C" fn aes256_encrypt_string(key: *const c_char, to_encrypt: *const c_char) -> *mut c_char {
    let string_key = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }.to_str().unwrap();

    let string_to_encrypt: &str = unsafe {
        assert!(!to_encrypt.is_null());

        CStr::from_ptr(to_encrypt)
    }.to_str().unwrap();

    
    let mc: magic_crypt::MagicCrypt256 = new_magic_crypt!(string_key, 256);
    let base64_string: CString = CString::new(mc.encrypt_str_to_base64(string_to_encrypt)).unwrap();
    return base64_string.into_raw();
}