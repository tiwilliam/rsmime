class RsmimeError(Exception):
    """Base class for all exceptions in this module.
    """
    ...

class CertificateError(RsmimeError):
    """Thrown when there is an error with the input certificate.
    """
    ...

class CertificateExpiredError(CertificateError):
    """Thrown when any certificate in the message has expired.
    """
    ...
    
class SignError(RsmimeError):
    """Thrown when there is an error signing the data.
    """
    ...

class VerifyError(RsmimeError):
    """Thrown when there is an error verifying the data.
    """
    ...
