##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""Tests for the WEBSERVER_JWT_* identity token verification."""

import time
import unittest
from unittest.mock import patch

from flask import Flask
from joserfc import jwt
from joserfc.jwk import RSAKey

import config
from pgadmin.utils import jwt_identity
from pgadmin.utils.route import BaseTestGenerator

ISSUER = 'https://issuer.example.com'
KEY = RSAKey.generate_key(2048, parameters={'kid': 'k1'})
OTHER_KEY = RSAKey.generate_key(2048, parameters={'kid': 'k1'})
NEW_KEY = RSAKey.generate_key(2048, parameters={'kid': 'k2'})


def _jwks(*keys):
    return {'keys': [k.as_dict(private=False) for k in keys]}


def _token(claims=None, key=KEY, **overrides):
    body = {'iss': ISSUER, 'aud': 'kubernetes', 'sub': 'u1',
            'common_name': 'jdoe', 'exp': int(time.time()) + 600,
            'amr': ['team-a']}
    body.update(claims or {})
    body.update(overrides)
    return jwt.encode({'alg': 'RS256', 'kid': key.kid}, body, key)


class _Session(dict):
    def __init__(self, sid):
        super().__init__()
        self.sid = sid


SETTINGS = {
    'WEBSERVER_JWT_HEADER': 'Authorization',
    'WEBSERVER_JWT_ISSUER': ISSUER,
    'WEBSERVER_JWT_AUDIENCE': ['kubernetes'],
    'WEBSERVER_JWT_JWKS_URL': 'https://issuer.example.com/jwks.json',
    'WEBSERVER_JWT_ALGORITHMS': ['RS256'],
    'WEBSERVER_JWT_USERNAME_CLAIM': 'common_name',
    'WEBSERVER_JWT_USERNAME_SUFFIX': '@example.com',
    'WEBSERVER_JWT_DENY_USERNAMES': ['anonymous'],
    'WEBSERVER_JWT_LEEWAY': 0,
    'WEBSERVER_JWT_JWKS_CACHE_SECONDS': 3600,
}


class _JWTTestCase:
    """Set-up shared by the tests below; not a test itself, and it skips
    BaseTestGenerator's database server set-up."""

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.patches = [patch.object(config, k, v)
                        for k, v in SETTINGS.items()]
        for p in self.patches:
            p.start()
        jwt_identity._key_set.clear()
        self.fetch = patch.object(jwt_identity, '_fetch_json',
                                  return_value=_jwks(KEY))
        self.fetched = self.fetch.start()
        self.app = Flask(__name__)

    def tearDown(self):
        self.fetch.stop()
        for p in self.patches:
            p.stop()
        jwt_identity._key_set.clear()
        jwt_identity._tokens.clear()


class TestValidTokenIsAccepted(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        claims = jwt_identity.verify_token(_token())
        self.assertEqual(claims['common_name'], 'jdoe')
        self.assertEqual(jwt_identity.username_from_claims(claims),
                         'jdoe@example.com')


class TestInvalidTokensAreRefused(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        bad = {
            'wrong issuer': _token(iss='https://evil.example.com'),
            'wrong audience': _token(aud='someone-else'),
            'expired': _token(exp=int(time.time()) - 60),
            'no expiry': _token(exp=None),
            'wrong key': _token(key=OTHER_KEY),
            'not a jwt': 'abc.def',
        }
        for label, token in bad.items():
            with self.subTest(label):
                with self.assertRaises(jwt_identity.JWTIdentityError):
                    jwt_identity.verify_token(token)


class TestAlgorithmNoneIsNeverAllowed(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        with patch.object(config, 'WEBSERVER_JWT_ALGORITHMS', ['none']):
            with self.assertRaises(jwt_identity.JWTIdentityError):
                jwt_identity.verify_token(_token())


class TestRotatedKeyIsFetchedAgain(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        jwt_identity.verify_token(_token())
        self.fetched.return_value = _jwks(KEY, NEW_KEY)
        # Pretend the cached set is older than the refetch rate limit.
        jwt_identity._key_set._fetched_at -= 120
        claims = jwt_identity.verify_token(_token(key=NEW_KEY))
        self.assertEqual(claims['sub'], 'u1')
        self.assertEqual(self.fetched.call_count, 2)


class TestUnknownKeyRefetchIsRateLimited(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        jwt_identity.verify_token(_token())
        for _ in range(3):
            with self.assertRaises(jwt_identity.JWTIdentityError):
                jwt_identity.verify_token(_token(key=NEW_KEY))
        self.assertEqual(self.fetched.call_count, 1)


class TestUserNames(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        name = jwt_identity.username_from_claims
        self.assertEqual(name({'common_name': 'a@b.c'}), 'a@b.c')
        self.assertIsNone(name({'common_name': 'anonymous'}))
        self.assertIsNone(name({'common_name': 'Anonymous'}))
        self.assertIsNone(name({'common_name': ''}))
        self.assertIsNone(name({}))


class TestTokenIsReadFromTheHeader(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        token = _token()
        for value in ('Bearer ' + token, 'bearer  ' + token, token):
            with self.app.test_request_context(
                    headers={'Authorization': value}):
                self.assertEqual(jwt_identity.read_token_from_request(),
                                 token)
        with self.app.test_request_context():
            self.assertIsNone(jwt_identity.identity_from_request())
        with self.app.test_request_context(
                headers={'Authorization': 'Bearer ' +
                         _token(common_name='anonymous')}):
            with self.assertRaises(jwt_identity.JWTIdentityError):
                jwt_identity.identity_from_request()


class TestTokensAreKeptPerSession(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        now = int(time.time())
        first = {'exp': now + 600}
        later = {'exp': now + 900}
        with self.app.test_request_context():
            with patch.object(jwt_identity, 'session', _Session('s1')):
                jwt_identity.remember_token('jdoe', later, 'later')
                # An earlier-expiring token does not replace a later one.
                jwt_identity.remember_token('jdoe', first, 'first')
                self.assertEqual(jwt_identity.current_token('jdoe'),
                                 ('later', later))
                self.assertIsNone(jwt_identity.current_token('someone'))
                # A token for another user does replace it.
                jwt_identity.remember_token('other', first, 'theirs')
                self.assertEqual(jwt_identity.current_token()[0], 'theirs')
            with patch.object(jwt_identity, 'session', _Session('s2')):
                self.assertIsNone(jwt_identity.current_token())
            with patch.object(jwt_identity, 'session', _Session('s1')):
                jwt_identity.forget_token()
                self.assertIsNone(jwt_identity.current_token())


class TestNearlyExpiredTokenIsNotHandedOut(_JWTTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        with self.app.test_request_context():
            with patch.object(jwt_identity, 'session', _Session('s1')):
                jwt_identity.remember_token(
                    'jdoe', {'exp': int(time.time()) + 5}, 'soon')
                self.assertIsNone(jwt_identity.current_token('jdoe'))
