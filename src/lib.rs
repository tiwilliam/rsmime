extern crate openssl;

use openssl::pkey;
use openssl::rsa::Rsa;
use pyo3::prelude::*;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;

pub fn _sign(cert_file: &str, key_file: &str, data_to_sign: &[u8]) -> Result<Vec<u8>, String> {
    let cert_data = std::fs::read(cert_file).map_err(|e| e.to_string())?;
    let key_data = std::fs::read(key_file).map_err(|e| e.to_string())?;

    let cert = X509::from_pem(&cert_data).expect("Failed to load cert");
    let pkey = pkey::PKey::from_rsa(Rsa::private_key_from_pem(&key_data).expect("Failed to load key")).unwrap();
    let certs = Stack::new().expect("Failed to create stack");

    let pkcs7 = Pkcs7::sign(cert.as_ref(), pkey.as_ref(), certs.as_ref(), data_to_sign, Pkcs7Flags::STREAM).expect("Failed to sign");
    let encrypted = pkcs7.to_smime(data_to_sign, Pkcs7Flags::STREAM).expect("Failed to convert to string");

    Ok(encrypted)
}

#[pyfunction]
fn sign(cert_file: &str, key_file: &str, data_to_sign: Vec<u8>) -> PyResult<String> {
    match _sign(cert_file, key_file, &data_to_sign) {
        Ok(signed_data) => {
            match String::from_utf8(signed_data) {
                Ok(signed_string) => Ok(signed_string),
                Err(err) => Err(pyo3::exceptions::PyException::new_err(err))
            }
        },
        Err(err) => Err(pyo3::exceptions::PyException::new_err(err)),
    }
}

#[pymodule]
fn rsmime(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    Ok(())
}
