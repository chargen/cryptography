# Stubs for cryptography.hazmat.primitives.hashes (Python 3.6)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Any, Optional, Protocol

class HashAlgorithmProtocol(Protocol):
    name: str = ...
    digest_size: int = ...

class HashAlgorithm:
    def name(self) -> str: ...
    def digest_size(self) -> int: ...

class HashContext:
    def algorithm(self) -> None: ...
    def update(self, data: Any) -> None: ...
    def finalize(self) -> None: ...
    def copy(self) -> None: ...

class Hash:
    def __init__(self, algorithm: Any, backend: Any, ctx: Optional[Any] = ...) -> None: ...
    _ctx: Any = ...
    algorithm: HashAlgorithmProtocol = ...
    def update(self, data: bytes) -> None: ...
    def copy(self) -> Hash: ...
    def finalize(self) -> bytes: ...

class SHA1:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class SHA224:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class SHA256:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class SHA384:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class SHA512:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class MD5:
    name: str = ...
    digest_size: int = ...
    block_size: int = ...

class BLAKE2b:
    name: str = ...
    block_size: int = ...
    def __init__(self, digest_size: Any) -> None: ...
    digest_size: Any = ...

class BLAKE2s:
    name: str = ...
    block_size: int = ...
    def __init__(self, digest_size: Any) -> None: ...
    digest_size: Any = ...
