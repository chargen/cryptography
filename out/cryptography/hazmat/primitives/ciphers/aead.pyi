# Stubs for cryptography.hazmat.primitives.ciphers.aead (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any

class ChaCha20Poly1305:
    def __init__(self, key: Any) -> None: ...
    @classmethod
    def generate_key(cls): ...
    def encrypt(self, nonce: Any, data: Any, associated_data: Any): ...
    def decrypt(self, nonce: Any, data: Any, associated_data: Any): ...

class AESCCM:
    def __init__(self, key: Any, tag_length: int = ...) -> None: ...
    @classmethod
    def generate_key(cls, bit_length: Any): ...
    def encrypt(self, nonce: Any, data: Any, associated_data: Any): ...
    def decrypt(self, nonce: Any, data: Any, associated_data: Any): ...

class AESGCM:
    def __init__(self, key: Any) -> None: ...
    @classmethod
    def generate_key(cls, bit_length: Any): ...
    def encrypt(self, nonce: Any, data: Any, associated_data: Any): ...
    def decrypt(self, nonce: Any, data: Any, associated_data: Any): ...
