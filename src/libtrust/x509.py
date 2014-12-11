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
import re

from cryptography.hazmat.primitives import hashes

from libtrust.cryptography_extras import backend


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
    key_digest = digest.finalize()[:240 // 8]

    b32_digest = base64.b32encode(key_digest)

    chunk_size = 4
    chunks = (b32_digest[i:i + chunk_size]
              for i in range(0, len(b32_digest), chunk_size))
    return ":".join(chunks)


def _make_libtrust_x509_certificate(backend, private_path, public_path):
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

    pem = _pem_selfsigned_libtrust_certificate(priv_key, pub_key, backend)


def _pem_selfsigned_libtrust_certificate(priv_key, pub_key, backend):
    if not isinstance(backend, libtrustBackend):
        raise TypeError(
            "Must use a libtrustBackend instance with this method."
        )

    _lib = backend._lib
    _ffi = backend._ffi

    evp_priv_key = backend._key_to_evp_pkey(priv_key)
    evp_pub_key = backend._key_to_evp_pkey(pub_key)

    fingerprint = libtrust_fingerprint(pub_key)

    # Make an empty certificate

    x509 = _lib.X509_new()
    assert x509 != _ffi.NULL
    x509 = backend._ffi.gc(x509, _lib.X509_free)

    # Setup some default values

    ret = _lib.X509_set_version(x509, 2)
    assert ret == 1

    ret = _lib.X509_gmtime_adj(
        _lib.X509_get_notBefore(x509),
        0
    )
    assert ret != _ffi.NULL

    ret = _lib.X509_gmtime_adj(
        _lib.X509_get_notAfter(x509),
        60 * 60 * 24
    )
    assert ret != _ffi.NULL

    # Add the public key

    ret = _lib.X509_set_pubkey(x509, evp_pub_key)
    assert ret == 1

    # Set the CN field to the fingerprint

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

    # Also the issuer

    ret = _lib.X509_set_issuer_name(x509, name)
    assert ret == 1

    # Add the key usage extension
    # TODO: actually give it a value.

    ctx = _ffi.new("X509V3_CTX*")
    _lib.X509V3_set_ctx_nodb(ctx)
    _lib.X509V3_set_ctx(ctx, x509, x509, _ffi.NULL, _ffi.NULL, 0)
    ex = _lib.X509V3_EXT_conf_nid(_ffi.NULL, ctx, _lib.NID_ext_key_usage, 0)
    _lib.X509_add_ext(x509, ex)
    _lib.X509_EXTENSION_free(ex)

    # Sign the certificate

    evp_sha256 = _lib.EVP_get_digestbyname("sha256".encode("ascii"))
    assert evp_sha256 != _ffi.NULL

    ret = _lib.X509_sign(x509, evp_priv_key, evp_sha256)
    assert ret > 0

    # Serialise to PEM

    bio = backend._create_mem_bio()
    ret = _lib.PEM_write_bio_X509(bio, x509)
    assert ret == 1

    return backend._read_mem_bio(bio)
