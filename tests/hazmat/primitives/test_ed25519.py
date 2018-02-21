# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import InvalidSignature, _Reasons
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

from ...utils import (
    load_vectors_from_file, raises_unsupported_algorithm
)


def load_ed25519_vectors(vector_data):
    """
    djb's ed25519 vectors are structured as a colon delimited array:
        0: secret key (32 bytes) + public key (32 bytes)
        1: public key (32 bytes)
        2: message (0+ bytes)
        3: signature + message (64+ bytes)
    """
    data = []
    for line in vector_data:
        x = line.split(':')
        secret_key = x[0][0:64]
        public_key = x[1]
        message = x[2]
        signature = x[3][0:128]
        data.append({
            "secret_key": secret_key,
            "public_key": public_key,
            "message": message,
            "signature": signature
        })
    return data


@pytest.mark.supported(
    only_if=lambda backend: not backend.ed25519_supported(),
    skip_message="Requires OpenSSL without Ed25519 support"
)
@pytest.mark.requires_backend_interface(interface=DHBackend)
def test_ed25519_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        Ed25519PublicKey.from_public_bytes(b"0" * 32)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        Ed25519PrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.ed25519_supported(),
    skip_message="Requires OpenSSL with Ed25519 support"
)
@pytest.mark.requires_backend_interface(interface=DHBackend)
class TestEd25519Signing(object):
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "Ed25519", "sign.input"),
            load_ed25519_vectors
        )
    )
    def test_sign_input(self, vector, backend):
        sk = binascii.unhexlify(vector["secret_key"])
        pk = binascii.unhexlify(vector["public_key"])
        message = binascii.unhexlify(vector["message"])
        signature = binascii.unhexlify(vector["signature"])
        private_key = Ed25519PrivateKey.from_private_bytes(sk)
        computed_sig = private_key.sign(message)
        assert computed_sig == signature
        public_key = private_key.public_key()
        assert public_key.public_bytes() == pk
        public_key.verify(signature, message)

    def test_invalid_signature(self, backend):
        key = Ed25519PrivateKey.generate()
        signature = key.sign(b"test data")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(signature, b"wrong data")

        with pytest.raises(InvalidSignature):
            key.public_key().verify(b"0" * 64, b"test data")

    def test_generate(self, backend):
        key = Ed25519PrivateKey.generate()
        assert key
        assert key.public_key()
