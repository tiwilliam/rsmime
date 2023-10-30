extern crate openssl;

use std::io::{Error, ErrorKind};

use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::Private;
use openssl::pkey::{PKey, PKeyRef};
use openssl::rsa::Rsa;
use openssl::stack::{Stack, StackRef};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Ref, X509};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pymodule;

fn _sign(
    stack: &StackRef<X509>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    message: &[u8],
    detached: bool,
) -> PyResult<Vec<u8>> {
    if message.is_empty() {
        return Err(SignError::new_err("Cannot sign empty data"));
    }

    let flags = if detached {
        Pkcs7Flags::DETACHED
    } else {
        Pkcs7Flags::empty()
    };

    let pkcs7 = Pkcs7::sign(cert, pkey, stack, message, flags)
        .map_err(|err| SignError::new_err(err.to_string()))?;
    let out = pkcs7
        .to_smime(message, flags)
        .map_err(|err| SignError::new_err(err.to_string()))?;

    Ok(out)
}

fn cert_subject_to_string(cert: &X509Ref, nid: Nid) -> String {
    let nid_entry = cert.subject_name().entries_by_nid(nid).next().unwrap();
    nid_entry.data().as_utf8().unwrap().to_string()
}

fn validate_expiry(certs: &StackRef<X509>) -> Result<(), Error> {
    for cert in certs.iter() {
        let expire = cert.not_after();
        if expire.le(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()) {
            let expire_string = expire.to_string();
            let subject_name = cert_subject_to_string(cert, Nid::COMMONNAME);
            return Err(Error::new(
                ErrorKind::Other,
                format!("Certificate {subject_name} expired {expire_string}"),
            ));
        }
    }
    Ok(())
}

fn _verify(message: &[u8], raise_on_expired: bool) -> PyResult<Vec<u8>> {
    let certs = Stack::new().unwrap();
    let store = X509StoreBuilder::new().unwrap().build();
    let mut out: Vec<u8> = Vec::new();

    let (pkcs7, indata) =
        Pkcs7::from_smime(message).map_err(|err| VerifyError::new_err(err.to_string()))?;

    if raise_on_expired {
        let signer_certs = pkcs7.signers(certs.as_ref(), Pkcs7Flags::empty()).unwrap();
        validate_expiry(signer_certs.as_ref())
            .map_err(|err| CertificateExpiredError::new_err(err.to_string()))?;
    }

    pkcs7
        .verify(
            certs.as_ref(),
            store.as_ref(),
            indata.as_deref(),
            Some(out.as_mut()),
            Pkcs7Flags::NOVERIFY,
        )
        .map_err(|err| VerifyError::new_err(err.to_string()))?;

    Ok(out)
}

create_exception!(exceptions, RsmimeError, PyException);
create_exception!(exceptions, CertificateError, RsmimeError);
create_exception!(exceptions, CertificateExpiredError, CertificateError);
create_exception!(exceptions, SignError, RsmimeError);
create_exception!(exceptions, VerifyError, RsmimeError);

#[pymodule]
fn exceptions(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("RsmimeError", py.get_type::<RsmimeError>())?;
    m.add("CertificateError", py.get_type::<CertificateError>())?;
    m.add(
        "CertificateExpiredError",
        py.get_type::<CertificateExpiredError>(),
    )?;
    m.add("SignError", py.get_type::<SignError>())?;
    m.add("VerifyError", py.get_type::<VerifyError>())?;
    Ok(())
}

#[pymodule]
fn rsmime(py: Python, m: &PyModule) -> PyResult<()> {
    let exceptions = wrap_pymodule!(exceptions);

    py.import("sys")?
        .getattr("modules")?
        .set_item("rsmime.exceptions", exceptions(py))?;

    m.add_wrapped(exceptions)?;
    m.add_class::<Rsmime>()?;

    Ok(())
}

#[pyclass]
struct Rsmime {
    stack: Stack<X509>,
    cert: X509,
    pkey: PKey<Private>,
}

#[pymethods]
impl Rsmime {
    #[new]
    #[pyo3(signature = (cert_file, key_file))]
    fn new(cert_file: String, key_file: String) -> PyResult<Self> {
        let stack = Stack::new().unwrap();

        let cert_data =
            std::fs::read(cert_file).map_err(|err| CertificateError::new_err(err.to_string()))?;

        let cert =
            X509::from_pem(&cert_data).map_err(|err| CertificateError::new_err(err.to_string()))?;

        let key_data =
            std::fs::read(key_file).map_err(|err| CertificateError::new_err(err.to_string()))?;

        let rsa = Rsa::private_key_from_pem(&key_data)
            .map_err(|err| CertificateError::new_err(err.to_string()))?;
        let pkey = PKey::from_rsa(rsa).map_err(|err| CertificateError::new_err(err.to_string()))?;

        Ok(Rsmime { stack, cert, pkey })
    }

    #[staticmethod]
    #[pyo3(signature = (message, *, raise_on_expired = false))]
    fn verify(py_: Python<'_>, message: Vec<u8>, raise_on_expired: bool) -> PyResult<PyObject> {
        match _verify(&message, raise_on_expired) {
            Ok(data) => Ok(PyBytes::new(py_, &data).into()),
            Err(err) => Err(err),
        }
    }

    #[pyo3(signature = (message, *, detached = false))]
    fn sign(self_: PyRef<'_, Self>, message: Vec<u8>, detached: bool) -> PyResult<PyObject> {
        match _sign(
            self_.stack.as_ref(),
            self_.cert.as_ref(),
            self_.pkey.as_ref(),
            &message,
            detached,
        ) {
            Ok(data) => Ok(PyBytes::new(self_.py(), &data).into()),
            Err(err) => Err(err),
        }
    }
}
