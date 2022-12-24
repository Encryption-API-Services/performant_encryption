use std::ffi::{c_char, CStr, CString};

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};


#[no_mangle]
pub extern "C" fn argon2_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let pass_bytes = unsafe{
        assert!(!pass_to_hash.is_null());
        CStr::from_ptr(pass_to_hash)
    }.to_str().unwrap().as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = CString::new(argon2.hash_password(pass_bytes, &salt).unwrap().to_string()).unwrap();
    return password_hash.into_raw();
}

#[test]
fn argon2_hash_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe{CString::from_raw(hashed_password_ptr)};
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}
