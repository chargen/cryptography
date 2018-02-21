# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import exceptions, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


@utils.register_interface(Ed25519PublicKey)
class _Ed25519PublicKey(object):
    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_bytes(self):
        bio = self._backend._create_mem_bio_gc()
        res = self._backend._lib.i2d_PUBKEY_bio(bio, self._evp_pkey)
        self._backend.openssl_assert(res == 1)
        asn1 = self._backend._read_mem_bio(bio)
        # We serialize to the ASN.1 structure defined in
        # https://tools.ietf.org/html/draft-ietf-curdle-pkix-03. and
        # then take the last 32 bytes, which are the actual key.
        return asn1[-32:]

    def verify(self, signature, data):
        evp_md_ctx = self._backend._lib.Cryptography_EVP_MD_CTX_new()
        self._backend.openssl_assert(evp_md_ctx != self._backend._ffi.NULL)
        evp_md_ctx = self._backend._ffi.gc(
            evp_md_ctx, self._backend._lib.Cryptography_EVP_MD_CTX_free
        )
        res = self._backend._lib.EVP_DigestVerifyInit(
            evp_md_ctx, self._backend._ffi.NULL, self._backend._ffi.NULL,
            self._backend._ffi.NULL, self._evp_pkey
        )
        self._backend.openssl_assert(res == 1)
        res = self._backend._lib.EVP_DigestVerify(
            evp_md_ctx, signature, len(signature), data, len(data)
        )
        if res != 1:
            self._backend._consume_errors()
            raise exceptions.InvalidSignature


@utils.register_interface(Ed25519PrivateKey)
class _Ed25519PrivateKey(object):
    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_key(self):
        bio = self._backend._create_mem_bio_gc()
        res = self._backend._lib.i2d_PUBKEY_bio(bio, self._evp_pkey)
        self._backend.openssl_assert(res == 1)
        evp_pkey = self._backend._lib.d2i_PUBKEY_bio(
            bio, self._backend._ffi.NULL
        )
        return _Ed25519PublicKey(self._backend, evp_pkey)

    def sign(self, data):
        evp_md_ctx = self._backend._lib.Cryptography_EVP_MD_CTX_new()
        self._backend.openssl_assert(evp_md_ctx != self._backend._ffi.NULL)
        evp_md_ctx = self._backend._ffi.gc(
            evp_md_ctx, self._backend._lib.Cryptography_EVP_MD_CTX_free
        )
        res = self._backend._lib.EVP_DigestSignInit(
            evp_md_ctx, self._backend._ffi.NULL, self._backend._ffi.NULL,
            self._backend._ffi.NULL, self._evp_pkey
        )
        self._backend.openssl_assert(res == 1)
        buf = self._backend._ffi.new("unsigned char[]", 64)
        buflen = self._backend._ffi.new("size_t *", len(buf))
        res = self._backend._lib.EVP_DigestSign(
            evp_md_ctx, buf, buflen, data, len(data)
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == 64)
        return self._backend._ffi.buffer(buf, buflen[0])[:]
