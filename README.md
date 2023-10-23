# rsmime

Rust powered Python package for signing data in S/MIME format

## Usage

```
import rsmime

raw_data = b'data to sign'
signed_data = rsmime.sign('something.crt', 'something.key', raw_data)
```