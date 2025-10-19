"""Public package interface for the compiled `rsmime` extension.

This module imports all public symbols from the compiled extension module and
adjusts metadata so that tools relying on introspection (e.g. mkdocstrings)
can correctly resolve symbols to this package namespace.
"""

# ruff: noqa
# type: ignore

from . import rsmime as _ext
from .rsmime import *  # re-export public API from the extension

# Propagate module docstring and explicit export list if present on the extension
__doc__ = getattr(_ext, "__doc__", __doc__)
if hasattr(_ext, "__all__"):
    __all__ = _ext.__all__

# Help documentation tools resolve symbols to this package instead of builtins.
try:  # best-effort: some attributes may be read-only depending on the build
    if hasattr(_ext, "Rsmime"):
        _ext.Rsmime.__module__ = __name__
except Exception:
    pass

# Ensure the exceptions submodule is available as `rsmime.exceptions` even if
# the extension exposes it under a top-level name.
try:
    import sys as _sys

    if hasattr(_ext, "exceptions"):
        _ext.exceptions.__name__ = f"{__name__}.exceptions"
        _ext.exceptions.__package__ = __name__
        _sys.modules.setdefault(f"{__name__}.exceptions", _ext.exceptions)
except Exception:
    pass
