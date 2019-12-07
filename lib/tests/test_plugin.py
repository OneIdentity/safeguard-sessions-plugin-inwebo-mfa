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
from ..plugin import Plugin
import copy
import pytest


@pytest.fixture
def plugin(plugin_config):
    return Plugin(configuration=plugin_config)


@pytest.fixture
def plugin_with_questions(plugin_config):
    return Plugin(
        configuration=plugin_config
        + """
[question_1]
key=q1
prompt=First question:
disable_echo=yes

[question_2]
key=q2
prompt=Second question:

[question_3]
key=q3
prompt=Third question:
"""
    )


@pytest.mark.interactive
def test_authenticate_using_push(plugin_with_questions, inwebo_user, interactive):
    interactive.message("We are expecting a successful inWebo authentication, so please ACCEPT it")
    sc = {}
    ck = {}
    result = plugin_with_questions.authenticate(
        gateway_user=inwebo_user, client_ip="1.2.3.4", key_value_pairs={}, cookie=ck, session_cookie=sc, protocol="ssh"
    )
    sc = result["session_cookie"]
    ck = result["cookie"]

    assert result["verdict"] == "NEEDINFO"
    assert len(result["question"]) == 3
    value, prompt, disable_echo = result["question"]
    assert value == "otp"
    assert "one-time" in prompt
    assert disable_echo is False

    # request push by sending a "" as OTP
    result = plugin_with_questions.authenticate(
        gateway_user=inwebo_user,
        client_ip="1.2.3.4",
        key_value_pairs={"otp": ""},
        session_cookie=sc,
        cookie=ck,
        protocol="ssh",
    )
    sc = result["session_cookie"]
    ck = result["cookie"]
    # we expect a NEEDINFO with the first question, after authentication succeeds

    assert result["verdict"] == "NEEDINFO"
    assert len(result["question"]) == 3
    key, prompt, disable_echo = result["question"]
    assert key == "q1"
    assert "First" in prompt

    result = plugin_with_questions.authenticate(
        gateway_user=inwebo_user,
        client_ip="1.2.3.4",
        key_value_pairs={"otp": "", "q1": "value1", "q2": "value2"},
        session_cookie=sc,
        cookie=ck,
        protocol="ssh",
    )
    sc = result["session_cookie"]
    ck = result["cookie"]

    # only 3rd question, as the first two was supplied in key_value_pairs already
    assert result["verdict"] == "NEEDINFO"
    assert len(result["question"]) == 3
    key, prompt, disable_echo = result["question"]
    assert key == "q3"
    assert "Third" in prompt

    # this should succeed, both the authentication went OK, plus the
    # responses to the questions are also present
    kvpairs = {"otp": "", "q1": "value1", "q2": "value2", "q3": "value3"}
    result = plugin_with_questions.authenticate(
        gateway_user=inwebo_user,
        client_ip="1.2.3.4",
        key_value_pairs=kvpairs,
        session_cookie=sc,
        cookie=ck,
        protocol="ssh",
    )

    assert result["verdict"] == "ACCEPT"
    assert result["session_cookie"]["questions"] == {"q1": "value1", "q2": "value2", "q3": "value3"}


def test_session_cookies_are_propagated_accross_authenticate(plugin):
    sc = {"foo": "bar", "bar": "foo"}
    result = plugin.authenticate(
        gateway_user="whitelisted",
        client_ip="1.2.3.4",
        key_value_pairs={},
        session_cookie=copy.deepcopy(sc),
        cookie={},
        protocol="ssh",
    )

    assert result["verdict"] == "NEEDINFO"
    assert sc.items() <= result["session_cookie"].items()
