##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""The per-request identity token check of JWT-mode Webserver
authentication (webserver._sync_jwt_session)."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask

import config
from pgadmin.authenticate import webserver
from pgadmin.utils.jwt_identity import JWTIdentityError
from pgadmin.utils.route import BaseTestGenerator


class _Session(dict):
    def __init__(self):
        super().__init__(auth_source_manager={'current_source': 'webserver'},
                         aws_iam_role='billing-ro')
        self.sid = 's1'


class _SyncTestCase:
    """Shared set-up for the tests below; not a test itself."""

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.app = Flask(__name__)
        self.app.logger = MagicMock()
        self.session = _Session()
        for p in [
            patch.object(config, 'SERVER_MODE', True),
            patch.object(config, 'WEBSERVER_JWT_HEADER', 'Authorization'),
            patch.object(webserver, 'session', self.session),
            patch.object(webserver, 'current_user', SimpleNamespace(
                is_authenticated=True, username='jdoe@example.com')),
        ]:
            p.start()
        self.logout = patch.object(webserver, 'logout_user').start()
        self.remember = patch.object(webserver, 'remember_token').start()
        self.forget = patch.object(webserver, 'forget_token').start()
        webserver._last_rejection.clear()

    def tearDown(self):
        patch.stopall()

    def sync(self, identity):
        kwargs = {'side_effect': identity} \
            if isinstance(identity, Exception) else {'return_value': identity}
        with self.app.test_request_context('/browser/'), \
                patch.object(webserver, 'identity_from_request', **kwargs):
            webserver._sync_jwt_session()


class TestValidTokenForTheSameUserIsRemembered(
        _SyncTestCase,
        BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.sync(('jdoe@example.com', {'exp': 1}, 'tok'))
        self.remember.assert_called_once_with(
            'jdoe@example.com', {'exp': 1}, 'tok')
        self.logout.assert_not_called()


class TestTokenForAnotherUserLogsOut(_SyncTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.sync(('mallory@example.com', {'exp': 1}, 'tok'))
        self.logout.assert_called_once()
        self.forget.assert_called_once()
        self.assertNotIn('aws_iam_role', self.session)


class TestInvalidOrMissingTokenKeepsTheSession(
        _SyncTestCase,
        BaseTestGenerator):
    """An anonymous or invalid token on one request must not end the
    session: that is what made /aws_iam/role answer 401."""
    scenarios = [('default', dict())]

    def runTest(self):
        for _ in range(3):
            self.sync(JWTIdentityError('does not name an acceptable user'))
        self.sync(None)
        self.logout.assert_not_called()
        self.remember.assert_not_called()
        self.assertEqual(self.session['aws_iam_role'], 'billing-ro')
        # Logged once for the session, not on every request.
        self.assertEqual(self.app.logger.warning.call_count, 1)
