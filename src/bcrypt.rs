use std::{ffi::{c_char, CString, CStr}};

use bcrypt::{hash, verify, DEFAULT_COST};

#[no_mangle]
pub extern "C" fn bcrypt_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }.to_str().unwrap();

    let hashed_password = CString::new(hash(string_pass, DEFAULT_COST).unwrap()).unwrap();
    return hashed_password.into_raw();
}

#[no_mangle]
pub extern "C" fn bcrypt_verify(pass: *const c_char, hash: *const c_char) -> bool {
    let string_pass = unsafe {
        assert!(!pass.is_null());

        CStr::from_ptr(pass)
    }.to_str().unwrap();

    let string_hash = unsafe {
        assert!(!hash.is_null());

        CStr::from_ptr(hash)
    }.to_str().unwrap();
    return verify(string_pass, string_hash).unwrap();
}