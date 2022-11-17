use std::{ffi::{c_char, CString, CStr}, iter};

use bcrypt::{hash, verify, DEFAULT_COST};

#[no_mangle]
pub extern "C" fn bcrypt_hash(pass_to_hash: &str) -> *mut c_char {
    let hashed_password = CString::new(hash(pass_to_hash, DEFAULT_COST).unwrap()).unwrap();
    return hashed_password.into_raw();
}

// must pass the string back into Rust to deallocate the memory as it is NOT thread safe
#[no_mangle]
pub extern "C" fn bcrypt_hash_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}