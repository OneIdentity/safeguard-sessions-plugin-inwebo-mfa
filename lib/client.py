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
from safeguard.sessions.plugin.mfa_client import (MFAClient, MFAAuthenticationFailure,
                                                  MFAServiceUnreachable)

import json
import re
import requests
import requests.packages.urllib3
from requests import request, RequestException
import time
import urllib
import tempfile


class InWeboClient(MFAClient):
    def __init__(self, baseuri, serviceid, client_cert,
                 timeout=60, httptimeout=15, pollinterval=1, ignore_connection_error=False):
        self.baseuri = baseuri
        self.serviceid = serviceid
        self.timeout = timeout
        self.httptimeout = httptimeout
        self.pollinterval = pollinterval
        self.user = None
        self.client_cert = client_cert
        super().__init__('SPS InWebo Plugin', ignore_connection_error)

    @classmethod
    def from_config(cls, configuration, section="inwebo"):
        baseuri = configuration.get(section, "api_url", default="https://api.myinwebo.com/FS/")
        service_id = configuration.get(section, "service_id", required=True)
        client_cert = configuration.get_certificate(section, "client_cert", required=True)
        timeout = configuration.getint(section, "timeout", 60)
        httptimeout = configuration.getint(section, "http_socket_timeout", 10)
        pollinterval = configuration.getfloat(section, "rest_poll_interval", 1)
        return cls(baseuri, service_id, client_cert, timeout, httptimeout, pollinterval)

    def otp_authenticate(self, user, passcode):
        return self._do_authentication(user, passcode)

    def push_authenticate(self, user):
        return self._do_authentication(user)

    def _do_authentication(self, user, passcode=""):
        try:
            result = self._authenticate(user, passcode)
        except RequestException as err:
            self.logger.error('InWebo access error: %s', err)
            raise MFAServiceUnreachable("InWebo is not reachable")

        if not result:
            raise MFAAuthenticationFailure("Internal error, _authenticate returned False instead of an exception")
        return True

    def _authenticate(self, user, passcode=""):
        self.user = user
        if passcode and passcode != '':
            self.logger.debug("Checking factor for OTP")
            return self._check_otp(passcode)
        else:
            self.logger.debug("Checking factor for PUSH")
            return self._check_push()

    def _check_push(self):
        self.logger.debug("Checking factor for PUSH 2.")
        params = {
            'action': 'pushAuthenticate',
            'serviceId': self.serviceid,
            'userId': self.user,
            'format': 'json',
        }
        self.logger.debug("Checking factor for PUSH 3.")
        result = self._query('', params)

        self.logger.debug("Checking factor for PUSH 4. %s", result)
        params = {
            'action': 'checkPushResult',
            'sessionId': result.get('sessionId'),
            'serviceId': self.serviceid,
            'userId': self.user,
            'format': 'json',
        }

        endtime = time.time() + self.timeout
        while time.time() < endtime:
            result = self._query('', params)
            if result.get('err') == 'OK':
                self.logger.info('Verification succeeded')
                return True
            elif result.get('err') == 'NOK:WAITING':
                self.logger.debug('Verification is awaiting user approval')
                time.sleep(self.pollinterval)
                continue
            else:
                self.logger.error('Verification failed. Status: %s, [%s]', result.get('err'), result)
                raise MFAAuthenticationFailure(result['err'])
        raise MFAAuthenticationFailure('Push notification timed out')

    def _check_otp(self, otp):
        self.logger.info("Checking OTP: %s", otp)

        params = {
            'action': 'authenticateExtended',
            'serviceId': self.serviceid,
            'userId': self.user,
            'token': otp,
            'format': 'json',
        }

        result = self._query('', params=params)
        self.logger.debug("Result: %s", result)
        if result.get('err') == 'OK':
            return True
        raise MFAAuthenticationFailure(result.get('err') or 'Unkown error')

    def _query(self, url, params=None):
        if re.match('^https://', url.lower()):
            url = url
        else:
            url = urllib.parse.urljoin(self.baseuri, url)
        url = url.rstrip('/')
        self.logger.debug("Sending request: %s, params: %s", url, params)
        try:
            with self._get_client_cert_as_file() as f:
                r = request(url=url, params=params, cert=f.name, verify=True, method='GET')
            self.logger.debug("Response: [%d/%s]:%s;", r.status_code, r.url, r.content)
            return r.json()
        except ValueError as err:
            self.logger.debug("%s", err)
            return json.loads('{{"err":"{}"}}'.format(err))
        except requests.HTTPError as err:
            self.logger.debug("%s", err)
            if err.code == 404 or err.code == 403:
                return json.loads('{{"err":"{}"}}'.format(err))
            else:
                raise

    def _get_client_cert_as_file(self):
        f = tempfile.NamedTemporaryFile()
        pem_cert = '{cert}\n{key}'.format(cert=self.client_cert.get('cert'),
                                          key=self.client_cert.get('key'))
        f.write(pem_cert.encode())
        f.flush()
        return f
