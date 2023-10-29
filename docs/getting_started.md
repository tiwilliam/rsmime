# Getting started

## Install

To install the latest version of rsmime, run the following command:

```bash
pip install rsmime
```

## Sign an attached message

```python
import rsmime
from rsmime.exceptions import SignError, CertificateError

raw_data = b'Some data to sign'

try:
    signed_data = rsmime.sign('some.crt', 'some.key', raw_data)
    print(signed_data.decode())
except (SignError, CertificateError) as e:
    print("Failed to sign:", e)
```

### Output

```bash
$ python sign.py
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIJbwYJKoZIhvcNAQcCoIIJYDCCCVwCAQExDzANBglghkgBZQMEAgEFADAwBgkq
...
gRUKfNnUOID3xMWl65crFoIyCA==


```

## Sign a detached message

```python
import rsmime
from rsmime.exceptions import SignError, CertificateError

raw_data = b'Some data to sign'

try:
    signed_data = rsmime.sign('some.crt', 'some.key', raw_data, detached=True)
    print(signed_data.decode())
except (SignError, CertificateError) as e:
    print("Failed to sign:", e)
```

### Output

```bash
$ python sign.py
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; boundary="----105EE7840E51906DEE5D8D34C7B68CFA"

This is an S/MIME signed message

------105EE7840E51906DEE5D8D34C7B68CFA
Some data to sign
------105EE7840E51906DEE5D8D34C7B68CFA
Content-Type: application/x-pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

MIIJSgYJKoZIhvcNAQcCoIIJOzCCCTcCAQExDzANBglghkgBZQMEAgEFADALBgkq
...
lV7oyQKEY6sVyQkWP2rPmtPs85hsmZGmej0Tx4x7

------105EE7840E51906DEE5D8D34C7B68CFA--


```

## Verify a signed message

```python
import rsmime
from rsmime.exceptions import VerifyError

signed_data = b'...'

try:
    raw_again = rsmime.verify(signed_data)
    print(raw_again.decode())
except VerifyError as e:
    print("Failed to verify:", e)
```

### Output

```bash
$ python verify.py
Some data to sign
```