# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import (
    InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.openssl.utils import (
    _calculate_digest_and_algorithm
)
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    AsymmetricSignatureContext, AsymmetricVerificationContext, ec
)


def _check_signature_algorithm(signature_algorithm):
    if not isinstance(signature_algorithm, ec.ECDSA):
        raise UnsupportedAlgorithm(
            "Unsupported elliptic curve signature algorithm.",
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)


def _ec_key_curve_sn(backend, ec_key):
    group = backend._lib.EC_KEY_get0_group(ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    nid = backend._lib.EC_GROUP_get_curve_name(group)
    # The following check is to find EC keys with unnamed curves and raise
    # an error for now.
    if nid == backend._lib.NID_undef:
        raise NotImplementedError(
            "ECDSA certificates with unnamed curves are unsupported "
            "at this time"
        )

    curve_name = backend._lib.OBJ_nid2sn(nid)
    backend.openssl_assert(curve_name != backend._ffi.NULL)

    sn = backend._ffi.string(curve_name).decode('ascii')
    return sn


def _mark_asn1_named_ec_curve(backend, ec_cdata):
    """
    Set the named curve flag on the EC_KEY. This causes OpenSSL to
    serialize EC keys along with their curve OID which makes
    deserialization easier.
    """

    backend._lib.EC_KEY_set_asn1_flag(
        ec_cdata, backend._lib.OPENSSL_EC_NAMED_CURVE
    )


def _sn_to_elliptic_curve(backend, sn):
    try:
        return ec._CURVE_TYPES[sn]()
    except KeyError:
        raise UnsupportedAlgorithm(
            "{0} is not a supported elliptic curve".format(sn),
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        )


def int2octets(x, qlen):
    return utils.int_to_bytes(x, (qlen + 7) // 8)


def bits2int(data, qlen):
    value = utils.int_from_bytes(data, 'big')
    # TODO: length of data...is this right? had a bug earlier where
    # we converted bytes to int and it was 255 bits, but really should have
    # been 256, so bytes seems like it migh be right.
    rem = len(data) * 8 - qlen
    if rem > 0:
        value = value >> rem

    return value


def bits2octets(backend, data, q, qlen):
    z1 = bits2int(data, qlen)
    z2 = z1 % backend._bn_to_int(q)
    return int2octets(z2, qlen)


def _generate_rfc6979_nonce(backend, algorithm, digest, private_key):
    _, get_func, group = backend._ec_key_determine_group_get_set_funcs(
        private_key._ec_key
    )
    order = backend._lib.EC_GROUP_get0_order(group)
    backend.openssl_assert(order != backend._ffi.NULL)
    qlen = backend._lib.BN_num_bits(order)

    # step a is hash the message to get a digest. the digest is passed in here
    # so step a is complete
    # step b, set v
    v = b"\x01" * algorithm.digest_size
    # step c, set k (hmac key)
    hmac_key = b"\x00" * algorithm.digest_size
    # step d, set K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
    pn = private_key.private_numbers()
    x = int2octets(pn.private_value, qlen)
    digest = bits2octets(backend, digest, order, qlen)
    hash_ctx.update(v + b"\x00" + x + digest)
    hmac_key = hash_ctx.finalize()
    # step e, set v to HMAC_K(V)
    hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
    hash_ctx.update(v)
    v = hash_ctx.finalize()
    # step f, set K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
    hash_ctx.update(v + b"\x01" + x + digest)
    hmac_key = hash_ctx.finalize()
    # step g, V = HMAC_K(V)
    hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
    hash_ctx.update(v)
    v = hash_ctx.finalize()
    # step h
    qlenceil = ((qlen + 7) // 8)
    while True:
        tlen = 0
        t = b""
        while tlen < qlenceil:
            h = hmac.HMAC(hmac_key, algorithm, backend)
            h.update(v)
            v = h.finalize()
            t += v
            tlen = len(t)

        k = bits2int(t, qlen)
        k = backend._int_to_bn(k)
        k = backend._ffi.gc(k, backend._lib.BN_free)
        backend.openssl_assert(k != backend._ffi.NULL)
        # Check to see if k is in [1, q-1]
        if (
            backend._lib.BN_is_zero(k) != 1 and
            backend._lib.BN_cmp(k, order) == -1
        ):
            with backend._tmp_bn_ctx() as bn_ctx:
                tmp_point = backend._lib.EC_POINT_new(group)
                backend.openssl_assert(tmp_point != backend._ffi.NULL)
                tmp_point = backend._ffi.gc(
                    tmp_point, backend._lib.EC_POINT_free)
                x = backend._lib.BN_new()
                backend.openssl_assert(x != backend._ffi.NULL)
                x = backend._ffi.gc(x, backend._lib.BN_free)
                res = backend._lib.EC_POINT_mul(
                    group, tmp_point, k, backend._ffi.NULL,
                    backend._ffi.NULL, bn_ctx
                )
                backend.openssl_assert(res == 1)
                # This uses either EC_POINT_get_affine_coordinates_GF2m or GFp
                # depending on group.
                res = get_func(group, tmp_point, x, backend._ffi.NULL, bn_ctx)
                backend.openssl_assert(res == 1)
                r = backend._lib.BN_new()
                backend.openssl_assert(r != backend._ffi.NULL)
                r = backend._ffi.gc(r, backend._lib.BN_free)
                res = backend._lib.BN_nnmod(r, x, order, bn_ctx)
                backend.openssl_assert(res == 1)
                if (
                    not backend._lib.BN_is_zero(r) and
                    not backend._lib.BN_is_zero(k)
                ):
                    backend._lib.BN_mod_inverse(k, k, order, bn_ctx)
                    backend.openssl_assert(k != backend._ffi.NULL)
                    break
        else:
            # k was too big or zero, set a new k/v and loop
            # K = HMAC_K(V || 0x00)
            # V = HMAC_K(V)
            hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
            hash_ctx.update(v + b"\x00")
            hmac_key = hash_ctx.finalize()
            hash_ctx = hmac.HMAC(hmac_key, algorithm, backend)
            hash_ctx.update(v)
            v = hash_ctx.finalize()

    return (k, r)


def _ecdsa_sig_sign(backend, private_key, data, algorithm):
    max_size = backend._lib.ECDSA_size(private_key._ec_key)
    backend.openssl_assert(max_size > 0)

    sigbuf = backend._ffi.new("unsigned char[]", max_size)
    siglen_ptr = backend._ffi.new("unsigned int[]", 1)
    kinv, rp = _generate_rfc6979_nonce(backend, algorithm, data, private_key)
    res = backend._lib.ECDSA_sign_ex(
        0, data, len(data), sigbuf, siglen_ptr, kinv, rp, private_key._ec_key
    )
    backend.openssl_assert(res == 1)
    return backend._ffi.buffer(sigbuf)[:siglen_ptr[0]]


def _ecdsa_sig_verify(backend, public_key, signature, data):
    res = backend._lib.ECDSA_verify(
        0, data, len(data), signature, len(signature), public_key._ec_key
    )
    if res != 1:
        backend._consume_errors()
        raise InvalidSignature
    return True


@utils.register_interface(AsymmetricSignatureContext)
class _ECDSASignatureContext(object):
    def __init__(self, backend, private_key, algorithm):
        self._backend = backend
        self._private_key = private_key
        self._digest = hashes.Hash(algorithm, backend)

    def update(self, data):
        self._digest.update(data)

    def finalize(self):
        digest = self._digest.finalize()

        return _ecdsa_sig_sign(self._backend, self._private_key, digest)


@utils.register_interface(AsymmetricVerificationContext)
class _ECDSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature
        self._digest = hashes.Hash(algorithm, backend)

    def update(self, data):
        self._digest.update(data)

    def verify(self):
        digest = self._digest.finalize()
        return _ecdsa_sig_verify(
            self._backend, self._public_key, self._signature, digest
        )


@utils.register_interface(ec.EllipticCurvePrivateKeyWithSerialization)
class _EllipticCurvePrivateKey(object):
    def __init__(self, backend, ec_key_cdata, evp_pkey):
        self._backend = backend
        _mark_asn1_named_ec_curve(backend, ec_key_cdata)
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = _sn_to_elliptic_curve(backend, sn)

    curve = utils.read_only_property("_curve")

    def signer(self, signature_algorithm):
        _check_signature_algorithm(signature_algorithm)
        return _ECDSASignatureContext(
            self._backend, self, signature_algorithm.algorithm
        )

    def exchange(self, algorithm, peer_public_key):
        if not (
            self._backend.elliptic_curve_exchange_algorithm_supported(
                algorithm, self.curve
            )
        ):
            raise UnsupportedAlgorithm(
                "This backend does not support the ECDH algorithm.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM
            )

        if peer_public_key.curve.name != self.curve.name:
            raise ValueError(
                "peer_public_key and self are not on the same curve"
            )

        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        z_len = (self._backend._lib.EC_GROUP_get_degree(group) + 7) // 8
        self._backend.openssl_assert(z_len > 0)
        z_buf = self._backend._ffi.new("uint8_t[]", z_len)
        peer_key = self._backend._lib.EC_KEY_get0_public_key(
            peer_public_key._ec_key
        )

        r = self._backend._lib.ECDH_compute_key(
            z_buf, z_len, peer_key, self._ec_key, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(r > 0)
        return self._backend._ffi.buffer(z_buf)[:z_len]

    def public_key(self):
        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        self._backend.openssl_assert(group != self._backend._ffi.NULL)

        curve_nid = self._backend._lib.EC_GROUP_get_curve_name(group)

        public_ec_key = self._backend._lib.EC_KEY_new_by_curve_name(curve_nid)
        self._backend.openssl_assert(public_ec_key != self._backend._ffi.NULL)
        public_ec_key = self._backend._ffi.gc(
            public_ec_key, self._backend._lib.EC_KEY_free
        )

        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)

        res = self._backend._lib.EC_KEY_set_public_key(public_ec_key, point)
        self._backend.openssl_assert(res == 1)

        evp_pkey = self._backend._ec_cdata_to_evp_pkey(public_ec_key)

        return _EllipticCurvePublicKey(self._backend, public_ec_key, evp_pkey)

    def private_numbers(self):
        bn = self._backend._lib.EC_KEY_get0_private_key(self._ec_key)
        private_value = self._backend._bn_to_int(bn)
        return ec.EllipticCurvePrivateNumbers(
            private_value=private_value,
            public_numbers=self.public_key().public_numbers()
        )

    def private_bytes(self, encoding, format, encryption_algorithm):
        return self._backend._private_key_bytes(
            encoding,
            format,
            encryption_algorithm,
            self._evp_pkey,
            self._ec_key
        )

    def sign(self, data, signature_algorithm):
        _check_signature_algorithm(signature_algorithm)
        data, algorithm = _calculate_digest_and_algorithm(
            self._backend, data, signature_algorithm._algorithm
        )
        return _ecdsa_sig_sign(self._backend, self, data, algorithm)


@utils.register_interface(ec.EllipticCurvePublicKeyWithSerialization)
class _EllipticCurvePublicKey(object):
    def __init__(self, backend, ec_key_cdata, evp_pkey):
        self._backend = backend
        _mark_asn1_named_ec_curve(backend, ec_key_cdata)
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = _sn_to_elliptic_curve(backend, sn)

    curve = utils.read_only_property("_curve")

    def verifier(self, signature, signature_algorithm):
        if not isinstance(signature, bytes):
            raise TypeError("signature must be bytes.")

        _check_signature_algorithm(signature_algorithm)
        return _ECDSAVerificationContext(
            self._backend, self, signature, signature_algorithm.algorithm
        )

    def public_numbers(self):
        get_func, group = (
            self._backend._ec_key_determine_group_get_func(self._ec_key)
        )
        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)

        with self._backend._tmp_bn_ctx() as bn_ctx:
            bn_x = self._backend._lib.BN_CTX_get(bn_ctx)
            bn_y = self._backend._lib.BN_CTX_get(bn_ctx)

            res = get_func(group, point, bn_x, bn_y, bn_ctx)
            self._backend.openssl_assert(res == 1)

            x = self._backend._bn_to_int(bn_x)
            y = self._backend._bn_to_int(bn_y)

        return ec.EllipticCurvePublicNumbers(
            x=x,
            y=y,
            curve=self._curve
        )

    def public_bytes(self, encoding, format):
        if format is serialization.PublicFormat.PKCS1:
            raise ValueError(
                "EC public keys do not support PKCS1 serialization"
            )

        return self._backend._public_key_bytes(
            encoding,
            format,
            self,
            self._evp_pkey,
            None
        )

    def verify(self, signature, data, signature_algorithm):
        _check_signature_algorithm(signature_algorithm)
        data, algorithm = _calculate_digest_and_algorithm(
            self._backend, data, signature_algorithm._algorithm
        )
        return _ecdsa_sig_verify(self._backend, self, signature, data)
