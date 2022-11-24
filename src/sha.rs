use std::ffi::{c_char, CStr, CString};

use rsa::signature::digest::core_api::CtVariableCoreWrapper;
use sha_crypt::{Sha512Params, sha512_simple, sha512_check};

#[no_mangle]
pub extern "C" fn sha512_hash_password(password: *const c_char) -> *mut c_char {
    let string_password = unsafe {
        assert!(!password.is_null());

        CStr::from_ptr(password)
    }.to_str().unwrap();

    let params = Sha512Params::new(10_000).expect("RandomError!");
    let hashed_password: CString = CString::new(sha512_simple(string_password, &params).unwrap()).unwrap();
    return hashed_password.into_raw();
} 

#[no_mangle]
pub extern "C" fn sha512_verify_password(password: *const c_char, hashed_password: *const c_char) -> bool {
    let string_password = unsafe {
        assert!(!password.is_null());

        CStr::from_ptr(password)
    }.to_str().unwrap();

    let string_hashed_password = unsafe {
        assert!(!hashed_password.is_null());

        CStr::from_ptr(hashed_password)
    }.to_str().unwrap();

    return sha512_check(string_password, &string_hashed_password).is_ok()
}