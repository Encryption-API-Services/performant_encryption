use std::ffi::{c_char, CStr, CString};

use sha3::{Digest, Sha3_512};

#[no_mangle]
pub extern "C" fn sha512(data_to_hash: *const c_char) -> *mut c_char {
    let data_to_hash_bytes = unsafe {
        assert!(!data_to_hash.is_null());
        CStr::from_ptr(data_to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_hash_bytes);
    let result = hasher.finalize();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}