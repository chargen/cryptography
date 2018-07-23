# Stubs for cryptography.hazmat.primitives.twofactor.hotp (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional

from cryptography.hazmat.primitives.hashes import HashAlgorithmProtocol

class HOTP:
    def __init__(self, key: bytes, length: int, algorithm: HashAlgorithmProtocol, backend: Any, enforce_key_length: bool = ...) -> None: ...
    def generate(self, counter: int): ...
    def verify(self, hotp: bytes, counter: int): ...
    def get_provisioning_uri(self, account_name: str, counter: int, issuer: Optional[str]): ...
    def _dynamic_truncate(self, counter: int) -> bytes: ...
