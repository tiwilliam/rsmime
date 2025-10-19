# Getting started

## Install

To install the latest version of rsmime, run the following command:

```bash
pip install rsmime
```

## Sign an attached message

```python
from rsmime import Rsmime
from rsmime.exceptions import SignError, CertificateError

client = Rsmime("some.crt", "some.key")

try:
    signed_data = client.sign(b"Some data to sign")
    print(signed_data.decode())
except (SignError, CertificateError) as e:
    print("Failed to sign:", e)
```

If you already have the PEM data in memory you can also provide it directly as text or
bytes-like objects:

```python
from pathlib import Path
from rsmime import Rsmime

certificate = Path("some.crt").read_text()
private_key = Path("some.key").read_text()

client = Rsmime(cert_data=certificate, key_data=private_key)

certificate_bytes = Path("some.crt").read_bytes()
private_key_bytes = Path("some.key").read_bytes()

client = Rsmime(cert_data=certificate_bytes, key_data=private_key_bytes)

client = Rsmime(
    cert_data=bytearray(Path("some.crt").read_bytes()),
    key_data=bytearray(Path("some.key").read_bytes()),
)
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
from rsmime import Rsmime
from rsmime.exceptions import SignError, CertificateError

client = Rsmime("some.crt", "some.key")

try:
    signed_data = client.sign(b"Some data to sign", detached=True)
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
from rsmime import Rsmime
from rsmime.exceptions import VerifyError

try:
    raw_again = Rsmime.verify(signed_data)
    print(raw_again.decode())
except VerifyError as e:
    print("Failed to verify:", e)
```

### Output

```bash
$ python verify.py
Some data to sign
```
