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

from libtrust.x509 import make_libtrust_x509_certificate


class Identity(object):
    def __init__(self, backend, private_path, public_path):
        self._backend = backend
        self._private_path = private_path
        self._public_path = public_path

        self._pem_x509_cert = make_libtrust_x509_certificate(
            backend, private_path, public_path
        )

identity = Identity(
    backend,
    "private_key.pem",
    "public_key.pem"
)
