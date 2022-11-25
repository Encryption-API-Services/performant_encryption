use std::ffi::{c_char, CStr, CString};

use scrypt::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Scrypt
};

#[no_mangle]
pub extern "C" fn scrypt_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash) 
    }.to_str().unwrap();

    let salt = SaltString::generate(&mut OsRng);
    let hashed = Scrypt.hash_password(string_pass.as_bytes(), &salt).unwrap().to_string();
    return CString::new(hashed).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn scrypt_verify(pass_to_check: *const c_char, hash_to_check: *const c_char) -> bool {
    let string_pass = unsafe {
        assert!(!pass_to_check.is_null());

        CStr::from_ptr(pass_to_check) 
    }.to_str().unwrap();

    let string_hash = unsafe {
        assert!(!hash_to_check.is_null());

        CStr::from_ptr(hash_to_check) 
    }.to_str().unwrap();

    
    let parsed_hash = PasswordHash::new(&string_hash).unwrap();
    return Scrypt.verify_password(string_pass.as_bytes(), &parsed_hash).is_ok();
}