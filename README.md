# rsmime

Rust powered Python package for signing data in S/MIME format

## Usage

### Install
```
pip install rsmime
```

### Sign
```py
import rsmime

raw_data = b'data to sign'

try:
    signed_data = rsmime.sign('some.crt', 'some.key', raw_data)
except (rsmime.SignError, rsmime.CertificateError) as e:
    print("Failed to sign:", e)

print(signed_data.decode())
```

```
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B
...
SwxRisLtodx8YQ7VoOLFi9FNoia3SsJtCnu2hILeobjPTnPCAL+8N2bc22MX44mc
AAAAAAAA
```

### Verify
```py
import rsmime

try:
    raw_data = rsmime.verify(signed_data)
except rsmime.VerifyError as e:
    print("Failed to verify:", e)

print(raw_data.decode())
```

```
data to sign
```