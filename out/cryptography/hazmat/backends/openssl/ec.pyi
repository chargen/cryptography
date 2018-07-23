# Stubs for cryptography.hazmat.backends.openssl.ec (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any

def _sn_to_elliptic_curve(backend: Any, sn: bytes) -> Any: ...

class _ECDSASignatureContext:
    def __init__(self, backend: Any, private_key: Any, algorithm: Any) -> None: ...
    def update(self, data: Any) -> None: ...
    def finalize(self): ...

class _ECDSAVerificationContext:
    def __init__(self, backend: Any, public_key: Any, signature: Any, algorithm: Any) -> None: ...
    def update(self, data: Any) -> None: ...
    def verify(self) -> None: ...

class _EllipticCurvePrivateKey:
    def __init__(self, backend: Any, ec_key_cdata: Any, evp_pkey: Any) -> None: ...
    curve: Any = ...
    @property
    def key_size(self): ...
    def signer(self, signature_algorithm: Any): ...
    def exchange(self, algorithm: Any, peer_public_key: Any): ...
    def public_key(self): ...
    def private_numbers(self): ...
    def private_bytes(self, encoding: Any, format: Any, encryption_algorithm: Any): ...
    def sign(self, data: Any, signature_algorithm: Any): ...

class _EllipticCurvePublicKey:
    def __init__(self, backend: Any, ec_key_cdata: Any, evp_pkey: Any) -> None: ...
    curve: Any = ...
    @property
    def key_size(self): ...
    def verifier(self, signature: Any, signature_algorithm: Any): ...
    def public_numbers(self): ...
    def public_bytes(self, encoding: Any, format: Any): ...
    def verify(self, signature: Any, data: Any, signature_algorithm: Any) -> None: ...
