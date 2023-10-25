class CertificateError(Exception):
    ...
    
class SignError(Exception):
    ...

class VerifyError(Exception):
    ...

def sign(cert_file: str, key_file: str, data_to_sign: bytes) -> bytes:
    ...

def verify(data_to_verify: bytes, throw_on_expiry: bool = False) -> bytes:
    ...
