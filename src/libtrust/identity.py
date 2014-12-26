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

import tempfile

from libtrust.cryptography_extras import backend
from libtrust import x509


class Identity(object):
    def __init__(self, private_path, public_path):
        self._private_path = private_path
        self._public_path = public_path

        priv_data, priv_headers = x509.split_pem_headers(
            open(private_path).read())
        self._private_temp = tempfile.NamedTemporaryFile()
        self._private_temp.write(priv_data)
        self._private_temp.flush()

        self._pem_x509_cert = x509._make_libtrust_x509_certificate(
            backend, private_path, public_path
        )

        self._cert_temp = tempfile.NamedTemporaryFile()
        self._cert_temp.write(self._pem_x509_cert)
        self._cert_temp.flush()

    @property
    def cert_path(self):
        return self._cert_temp.name

    @property
    def private_key_path(self):
        return self._private_temp.name
