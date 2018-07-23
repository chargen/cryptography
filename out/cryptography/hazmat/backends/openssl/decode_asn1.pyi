# Stubs for cryptography.hazmat.backends.openssl.decode_asn1 (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from asn1crypto.core import SequenceOf
from typing import Any

class _Integers(SequenceOf): ...

class _X509ExtensionParser:
    ext_count: Any = ...
    get_ext: Any = ...
    handlers: Any = ...
    def __init__(self, ext_count: Any, get_ext: Any, handlers: Any) -> None: ...
    def parse(self, backend: Any, x509_obj: Any): ...
