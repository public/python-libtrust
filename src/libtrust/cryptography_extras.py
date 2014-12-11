# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.backend import (
    Backend as OpenSSLBackend
)
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey, _EllipticCurvePublicKey
)


class _X509Certificate(object):
    def __init__(self, backend, x509):
        self._backend = backend
        self._x509 = x509

    def fingerprint(self, algorithm):
        h = hashes.Hash(algorithm, self._backend)
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.i2d_X509_bio(
            bio, self._x509
        )
        assert res == 1
        der = self._backend._read_mem_bio(bio)
        h.update(der)
        return h.finalize()

    @property
    def version(self):
        version = self._backend._lib.X509_get_version(self._x509)
        if version == 0:
            return x509.X509Version.v1
        elif version == 2:
            return x509.X509Version.v3
        else:
            raise x509.InvalidX509Version(
                "{0} is not a valid X509 version".format(version)
            )

    @property
    def serial(self):
        asn1_int = self._backend._lib.X509_get_serialNumber(self._x509)
        assert asn1_int != self._backend._ffi.NULL
        bn = self._backend._lib.ASN1_INTEGER_to_BN(
            asn1_int, self._backend._ffi.NULL
        )
        assert bn != self._backend._ffi.NULL
        serial = self._backend._lib.BN_bn2hex(bn)
        assert serial != self._backend._ffi.NULL
        return int(self._backend._ffi.string(serial), 16)

    def public_key(self):
        pkey = self._backend._lib.X509_get_pubkey(self._x509)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def not_before(self):
        asn1_time = self._backend._lib.X509_get_notBefore(self._x509)
        return self._parse_asn1_time(asn1_time)

    @property
    def not_after(self):
        asn1_time = self._backend._lib.X509_get_notAfter(self._x509)
        return self._parse_asn1_time(asn1_time)

    def _parse_asn1_time(self, asn1_time):
        assert asn1_time != self._backend._ffi.NULL
        generalized_time = self._backend._lib.ASN1_TIME_to_generalizedtime(
            asn1_time, self._backend._ffi.NULL
        )
        assert generalized_time != self._backend._ffi.NULL
        generalized_time = self._backend._ffi.gc(
            generalized_time, self._backend._lib.ASN1_GENERALIZEDTIME_free
        )
        time = self._backend._ffi.string(
            self._backend._lib.ASN1_STRING_data(
                self._backend._ffi.cast("ASN1_STRING *", generalized_time)
            )
        ).decode("ascii")
        return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")


class Backend(OpenSSLBackend):
    def _create_mem_bio(self):
        bio_method = self._lib.BIO_s_mem()
        assert bio_method != self._ffi.NULL
        bio = self._lib.BIO_new(bio_method)
        assert bio != self._ffi.NULL
        bio = self._ffi.gc(bio, self._lib.BIO_free)
        return bio

    def _read_mem_bio(self, bio):
        buf = self._ffi.new("char **")
        buf_len = self._lib.BIO_get_mem_data(bio, buf)
        assert buf_len > 0
        assert buf[0] != self._ffi.NULL
        bio_data = self._ffi.buffer(buf[0], buf_len)[:]
        return bio_data

    def load_pem_x509_certificate(self, data):
        mem_bio = self._bytes_to_bio(data)
        x509 = self._lib.PEM_read_bio_X509(
        mem_bio.bio, self._ffi.NULL, self._ffi.NULL, self._ffi.NULL
        )
        if x509 == self._ffi.NULL:
            self._consume_errors()
            raise ValueError("Unable to load certificate")

        x509 = self._ffi.gc(x509, self._lib.X509_free)
        return _X509Certificate(self, x509)

    def dump_der_public_key(self, pub_key):
        cdata = pub_key._ec_key

        bio = self._create_mem_bio()
        ret = self._lib.i2d_EC_PUBKEY_bio(bio, cdata)
        assert ret == 1
        return self._read_mem_bio(bio)

    def _key_to_evp_pkey(self, key):
        evp_pkey = self._lib.EVP_PKEY_new()
        assert evp_pkey != self._ffi.NULL
        evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)

        if (
            isinstance(
                key,
                (_EllipticCurvePrivateKey, _EllipticCurvePublicKey)
            )
        ):
            self._lib.EVP_PKEY_set1_EC_KEY(
                evp_pkey,
                key._ec_key
            )
        else:
            raise TypeError()

        return evp_pkey


backend = Backend()
