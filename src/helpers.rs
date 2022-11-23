use std::ffi::{c_char, CString};

#[no_mangle]
pub extern "C" fn free_cstring_memory(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}