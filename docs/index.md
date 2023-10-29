# Documentation

<a href="https://pypi.org/project/rsmime/">![PyPI](https://img.shields.io/pypi/v/rsmime?color=gr&style=for-the-badge)</a>

Python package for signing and verifying S/MIME messages.

This package is written in Rust using [PyO3](https://pyo3.rs/). Signing and verification is handled by [OpenSSL](https://www.openssl.org/) which is statically linked to the package to simplify installation and dependency management. Runtime dependencies are limited to the Python standard library.

## API Reference

::: rsmime.Rsmime
::: rsmime.exceptions
