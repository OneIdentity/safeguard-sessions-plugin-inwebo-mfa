#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from ..client import InWeboClient
import pytest


@pytest.fixture
def client(site_parameters):
    cert = {'cert': [], 'key': []}
    selector = None
    for line in site_parameters['client_cert'].splitlines():
        if '-----BEGIN CERTIFICATE-----' in line:
            selector = 'cert'
        elif '-----BEGIN RSA PRIVATE KEY-----' in line:
            selector = 'key'
        if selector:
            cert[selector].append(line)

    baseurl = 'https://api.myinwebo.com/FS/'
    service_id = site_parameters['service_id']
    return InWeboClient(baseurl, service_id, cert)


@pytest.mark.interactive
def test_can_authenticate_with_push_notification(client, inwebo_user):
    assert client.push_authenticate(inwebo_user)


@pytest.mark.interactive
def test_can_authenticate_with_otp(client, inwebo_user, interactive):
    otp = interactive.askforinput('Please enter OTP: ')
    assert client.otp_authenticate(inwebo_user, otp)
