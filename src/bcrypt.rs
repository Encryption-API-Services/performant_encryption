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

#[test]
fn bcrypt_hash_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = bcrypt_hash(passsword_ptr);
    let hashed_password_ctr = unsafe {CString::from_raw(hashed_password) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(hashed_password_str, password);
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

#[test]
fn bcrypt_verify_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = bcrypt_hash(password_ptr);
    let hashed_password_ctr =  unsafe {CString::from_raw(hashed_password)};
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = bcrypt_verify(password_ptr, hashed_password_ptr);
    assert_eq!(true, is_valid);
}