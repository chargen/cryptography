# Stubs for cryptography.hazmat.backends.openssl.rsa (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any

class _RSASignatureContext:
    def __init__(self, backend: Any, private_key: Any, padding: Any, algorithm: Any) -> None: ...
    def update(self, data: Any) -> None: ...
    def finalize(self): ...

class _RSAVerificationContext:
    def __init__(self, backend: Any, public_key: Any, signature: Any, padding: Any, algorithm: Any) -> None: ...
    def update(self, data: Any) -> None: ...
    def verify(self): ...

class _RSAPrivateKey:
    def __init__(self, backend: Any, rsa_cdata: Any, evp_pkey: Any) -> None: ...
    key_size: Any = ...
    def signer(self, padding: Any, algorithm: Any): ...
    def decrypt(self, ciphertext: Any, padding: Any): ...
    def public_key(self): ...
    def private_numbers(self): ...
    def private_bytes(self, encoding: Any, format: Any, encryption_algorithm: Any): ...
    def sign(self, data: Any, padding: Any, algorithm: Any): ...

class _RSAPublicKey:
    def __init__(self, backend: Any, rsa_cdata: Any, evp_pkey: Any) -> None: ...
    key_size: Any = ...
    def verifier(self, signature: Any, padding: Any, algorithm: Any): ...
    def encrypt(self, plaintext: Any, padding: Any): ...
    def public_numbers(self): ...
    def public_bytes(self, encoding: Any, format: Any): ...
    def verify(self, signature: Any, data: Any, padding: Any, algorithm: Any): ...
