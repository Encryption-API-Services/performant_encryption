use bcrypt::{hash, verify, DEFAULT_COST};

#[no_mangle]
pub extern "C" fn bcrypt_hash(pass_to_hash: &str) -> String {
    let hashed_password = hash(pass_to_hash, DEFAULT_COST);
    hashed_password.unwrap()
}