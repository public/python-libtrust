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

import base64
from binascii import hexlify
import os
import re

from cryptography.hazmat.backends.openssl.backend import (
    Backend as OpenSSLBackend
)
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey, _EllipticCurvePublicKey
)
from cryptography.hazmat.primitives import hashes

client_data = (
    "/home/alex/code/src/github.com"
    "/docker/libtrust/tlsdemo/client_data"
)
os.chdir(client_data)


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


class libtrustBackend(OpenSSLBackend):
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


class libtrustIdentity(object):
    def __init__(self, backend, private_path, public_path):
        self._backend = backend
        self._private_path = private_path
        self._public_path = public_path

        self._x509_cert = make_libtrust_x509_certificate(
            backend, private_path, public_path
        )


PEM_BEGIN_RX = re.compile(r"^(-----BEGIN .*-----)$")
PEM_HEADER_RX = re.compile(r"^(.*): (.*)$")
PEM_END_RX = re.compile(r"^(-----END .*-----)$")
def split_pem_headers(data):
    """
    Filter the headers and PEM body into separate variables.

    OpenSSL's parser can't cope with PEM headers it doesn't expect so
    we need to clean them up for it.

    TODO: Don't remove DEK-Info etc from main PEM data?
    """

    headers = []
    body = []
    in_pem = False
    for line in data.splitlines():
        if not in_pem and PEM_BEGIN_RX.match(line):
            in_pem = True
            body.append(line)

        elif line and in_pem:
            match_headers = PEM_HEADER_RX.match(line)
            if match_headers:
                headers.append(match_headers.groups())

            elif PEM_END_RX.match(line):
                body.append(line)
                break
            else:
                body.append(line)

    return "\n".join(body), headers


def libtrust_fingerprint(public_key):
    """
    Generate a libtrust compatible fingerprint from a public key.

    This is currently defined as the first 240 bits of the SHA256 of the
    DER encoded SubjectPublicKeyInfo structure encoded in Base-32 in
    4 character chunks, separated by colons (":").
    """

    pub_key_der = backend.dump_der_public_key(public_key)
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(pub_key_der)
    key_digest = digest.finalize()[:240//8]

    b32_digest = base64.b32encode(key_digest)

    chunk_size = 4
    chunks = (b32_digest[i:i + chunk_size]
     for i in range(0, len(b32_digest), chunk_size))
    return ":".join(chunks)


def make_libtrust_x509_certificate(backend, private_path, public_path):
    """
    Load existing key material and generate a self signed libtrust x509
    certificate.
    """

    priv_data = open(private_path, "rb").read()
    pub_data = open(public_path, "rb").read()

    priv_data, priv_headers = split_pem_headers(priv_data)
    pub_data, pub_headers = split_pem_headers(pub_data)

    priv_key = backend.load_pem_private_key(priv_data, None)
    pub_key = backend.load_pem_public_key(pub_data)

    evp_priv_key = backend._key_to_evp_pkey(priv_key)
    evp_pub_key = backend._key_to_evp_pkey(pub_key)

    fingerprint = libtrust_fingerprint(pub_key)

    _lib = backend._lib
    _ffi = backend._ffi

    x509 = _lib.X509_new()
    assert x509 != _ffi.NULL
    x509 = backend._ffi.gc(x509, _lib.X509_free)

    ret = _lib.X509_set_version(x509, 2)
    assert ret == 1

    ret = _lib.X509_gmtime_adj(
        _lib.X509_get_notBefore(x509),
        0
    )
    assert ret != _ffi.NULL

    ret = _lib.X509_gmtime_adj(
        _lib.X509_get_notAfter(x509),
        60*60*24*365
    )
    assert ret != _ffi.NULL

    ret = _lib.X509_set_pubkey(x509, evp_pub_key)
    assert ret == 1

    name = _lib.X509_get_subject_name(x509)
    assert name != _ffi.NULL

    cn_obj = _lib.OBJ_txt2obj("CN", 0)
    assert cn_obj != _ffi.NULL
    cn_nid = _lib.OBJ_obj2nid(cn_obj)
    assert cn_nid != 0

    ret = _lib.X509_NAME_add_entry_by_NID(
        name,
        cn_nid,
        _lib.MBSTRING_UTF8,
        fingerprint,
        -1, -1, 0
    )
    assert ret == 1

    ret = _lib.X509_set_issuer_name(x509, name)
    assert ret == 1

    evp_sha256 = _lib.EVP_get_digestbyname("sha256".encode("ascii"))
    assert evp_sha256 != _ffi.NULL

    ret = _lib.X509_sign(x509, evp_priv_key, evp_sha256)
    assert ret > 0

    bio = backend._create_mem_bio()
    _lib.X509_print_ex(bio, x509, 0, 0)

    print(backend._read_mem_bio(bio))
    print()

    bio = backend._create_mem_bio()
    _lib.PEM_write_bio_X509(bio, x509)
    print(backend._read_mem_bio(bio))


backend = libtrustBackend()

identity = libtrustIdentity(
    backend,
    "private_key.pem",
    "public_key.pem"
)
