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
import pytest
from textwrap import dedent


@pytest.fixture
def inwebo_user(site_parameters):
    return site_parameters['username']


@pytest.fixture
def plugin_config(site_parameters):
    conf = dedent("""
        [inwebo]
        service_id={service_id}
        api_url: https://api.myinwebo.com/FS/
        client_cert=
        {client_cert}
        timeout=25
        http_socket_timeout=20
        rest_poll_interval=0.1
    """).format(
        service_id=site_parameters['service_id'],
        client_cert=''.join([' ' + line for line in site_parameters['client_cert'].splitlines()]),
    )
    print(conf)
    return conf
