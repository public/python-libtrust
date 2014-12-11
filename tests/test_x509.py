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

from cryptography.hazmat.primitives.serialization import load_pem_public_key

import pytest

import libtrust.cryptography_extras
import libtrust.x509

from tests.utils import load_test_data


@pytest.fixture
def backend():
    return libtrust.cryptography_extras.backend


@pytest.fixture
def public_key(backend):
    pem = load_test_data("public_key.pem")
    data, headers = libtrust.x509.split_pem_headers(pem)
    return load_pem_public_key(data, backend)


def test_split_pem_headers(backend):
    pem = load_test_data("public_key.pem")
    data, headers = libtrust.x509.split_pem_headers(pem)
    assert headers == [
        (
            b'comment',
            b'TLS Demo Client'
        ),
        (
            b'keyID',
            b'PG2J:H3RO:U6YF:N4XN:FB52:Y55J:G6IG:CLB6:SL6Q:NFFM:OTKI:NEKT'
        )
    ]


def test_fingerprint(public_key):
    assert libtrust.x509.libtrust_fingerprint(public_key) == (
        b"PG2J:H3RO:U6YF:N4XN:FB52:Y55J:G6IG:CLB6:SL6Q:NFFM:OTKI:NEKT"
    )
