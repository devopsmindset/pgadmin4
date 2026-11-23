##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""Tests for AWS IAM database authentication with the user's own web
identity (pgadmin.utils.aws_iam)."""

import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask
from flask_babel import Babel

import config
from pgadmin.utils import aws_iam, passexec
from pgadmin.utils.route import BaseTestGenerator

ROLES = [
    {'id': 'billing-ro', 'label': 'Billing (read only)',
     'arn': 'arn:aws:iam::111111111111:role/billing-ro',
     'claim_values': ['billing'], 'db_user': '{local_username}_ro'},
    {'id': 'billing-rw', 'label': 'Billing (write)',
     'arn': 'arn:aws:iam::111111111111:role/billing-rw',
     'claim_values': ['billing-admins'], 'db_user': 'app_rw'},
    {'id': 'shared', 'arn': 'arn:aws:iam::222222222222:role/path/shared'},
    {'id': 'broken', 'arn': 'not-an-arn'},
    {'id': 'bad-db-user', 'arn': 'arn:aws:iam::111111111111:role/x',
     'db_user': '{nope}'},
    {'id': 'billing-ro', 'arn': 'arn:aws:iam::111111111111:role/dup'},
    'not a dict',
]

RDS_HOST = 'db1.abcdefghijkl.eu-central-1.rds.amazonaws.com'


class _Session(dict):
    def __init__(self, sid='s1'):
        super().__init__()
        self.sid = sid


def _sts_response(arn='arn:aws:sts::111:assumed-role/x/jdoe', minutes=60):
    return {
        'Credentials': {
            'AccessKeyId': 'ASIAEXAMPLE', 'SecretAccessKey': 'secret',
            'SessionToken': 'session',
            'Expiration': datetime.now(timezone.utc) +
            timedelta(minutes=minutes),
        },
        'AssumedRoleUser': {'Arn': arn},
    }


def _client_error(code, message=''):
    from botocore.exceptions import ClientError
    return ClientError({'Error': {'Code': code, 'Message': message}},
                       'AssumeRoleWithWebIdentity')


class _AwsTestCase:
    """Set-up shared by the tests below; not a test itself, and it skips
    BaseTestGenerator's database server set-up."""

    claims = {'common_name': 'jdoe', 'amr': ['billing'],
              'exp': int(time.time()) + 3600}

    def setUp(self):
        unittest.TestCase.setUp(self)
        settings = {
            'SERVER_MODE': True, 'AWS_IAM_ENABLED': True,
            'AWS_IAM_ROLES': ROLES, 'AWS_IAM_ROLE_CLAIM': 'amr',
            'AWS_IAM_PROBE_ROLES': True, 'AWS_IAM_REQUIRE_ROLE': True,
            'AWS_IAM_DEFAULT_REGION': None, 'AWS_IAM_STS_REGION': None,
            'AWS_IAM_SESSION_DURATION': 3600,
            'AWS_IAM_RDS_TOKEN_REUSE_SECONDS': 600,
            # Most tests below also cover per-server roles.
            'AWS_IAM_SESSION_ROLE_ONLY': False,
            'AWS_IAM_ALLOW_ROLE_SWITCH': True,
            'SERVER_PASSEXEC_COMMANDS': {'vault': ['/bin/true']},
        }
        self.patches = [patch.object(config, k, v)
                        for k, v in settings.items()]
        self.session = _Session()
        self.user = SimpleNamespace(is_authenticated=True, username='jdoe',
                                    id=1)
        self.sts = MagicMock()
        self.sts.assume_role_with_web_identity.return_value = \
            _sts_response()
        self.patches += [
            patch.object(aws_iam, 'session', self.session),
            patch.object(aws_iam, 'current_user', self.user),
            patch.object(aws_iam, '_sts_client', return_value=self.sts),
            patch.object(aws_iam.jwt_identity, 'current_token',
                         side_effect=lambda u=None: ('jwt', self.claims)),
        ]
        for p in self.patches:
            p.start()
        aws_iam._credentials.clear()
        self.app = Flask(__name__)
        Babel(self.app)
        self.ctx = self.app.test_request_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()
        for p in reversed(self.patches):
            p.stop()
        aws_iam._credentials.clear()


class TestRoleConfiguration(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        ids = [r['id'] for r in aws_iam.configured_roles()]
        self.assertEqual(ids, ['billing-ro', 'billing-rw', 'shared'])
        shared = aws_iam.find_role('shared')
        self.assertEqual(shared['account'], '222222222222')
        self.assertEqual(shared['name'], 'shared')
        self.assertEqual(shared['label'], 'shared')
        self.assertTrue(aws_iam.is_enabled())
        with patch.object(config, 'SERVER_MODE', False):
            self.assertFalse(aws_iam.is_enabled())


class TestRolesAreFilteredByClaim(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        ids = [r['id'] for r in aws_iam.candidate_roles(self.claims)]
        self.assertEqual(ids, ['billing-ro', 'shared'])
        ids = [r['id'] for r in aws_iam.candidate_roles({'amr': 'nothing'})]
        self.assertEqual(ids, ['shared'])
        with patch.object(config, 'AWS_IAM_ROLE_CLAIM', None):
            self.assertEqual(len(aws_iam.candidate_roles({})), 3)


class TestCredentialsAreAssumedAndReused(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        role = aws_iam.find_role('billing-ro')
        first = aws_iam.role_credentials(role)
        second = aws_iam.role_credentials(role)
        self.assertEqual(first, second)
        self.assertEqual(first['aws_session_token'], 'session')
        self.sts.assume_role_with_web_identity.assert_called_once_with(
            RoleArn=role['arn'], RoleSessionName='jdoe',
            WebIdentityToken='jwt', DurationSeconds=3600)
        info = aws_iam.credentials_info(role)
        self.assertEqual(info['assumed_arn'],
                         'arn:aws:sts::111:assumed-role/x/jdoe')


class TestCredentialsNearExpiryAreRenewed(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.sts.assume_role_with_web_identity.return_value = \
            _sts_response(minutes=2)
        role = aws_iam.find_role('billing-ro')
        aws_iam.role_credentials(role)
        aws_iam.role_credentials(role)
        self.assertEqual(
            self.sts.assume_role_with_web_identity.call_count, 2)


class TestRefusalIsReportedAndCached(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.sts.assume_role_with_web_identity.side_effect = \
            _client_error('AccessDenied')
        role = aws_iam.find_role('shared')
        for _ in range(2):
            with self.assertRaises(aws_iam.AwsIamError) as e:
                aws_iam.role_credentials(role)
            self.assertIn('not allowed', str(e.exception))
        self.assertEqual(
            self.sts.assume_role_with_web_identity.call_count, 1)


class TestTooLongDurationFallsBack(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.sts.assume_role_with_web_identity.side_effect = [
            _client_error('ValidationError',
                          'The requested DurationSeconds exceeds the '
                          'MaxSessionDuration set for this role.'),
            _sts_response()]
        with patch.object(config, 'AWS_IAM_SESSION_DURATION', 14400):
            aws_iam.role_credentials(aws_iam.find_role('shared'))
        durations = [c.kwargs['DurationSeconds'] for c in
                     self.sts.assume_role_with_web_identity.call_args_list]
        self.assertEqual(durations, [14400, 3600])


class TestAvailableRolesReportRefusals(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        def assume(**kwargs):
            if kwargs['RoleArn'].endswith('/shared'):
                raise _client_error('AccessDenied')
            return _sts_response()
        self.sts.assume_role_with_web_identity.side_effect = assume
        result = {r['id']: err for r, err in aws_iam.available_roles()}
        self.assertEqual(set(result), {'billing-ro', 'shared'})
        self.assertIsNone(result['billing-ro'])
        self.assertIsNotNone(result['shared'])
        # The only usable role is selected automatically.
        self.assertFalse(aws_iam.selection_required())
        self.assertEqual(aws_iam.selected_role()['id'], 'billing-ro')


class TestSelectionIsRequiredWithSeveralRoles(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.assertTrue(aws_iam.selection_required())
        with patch.object(aws_iam, 'release_selected_role_connections') as r:
            aws_iam.select_role('shared')
            r.assert_not_called()
            self.assertFalse(aws_iam.selection_required())
            aws_iam.select_role('billing-ro')
            r.assert_called_once()
        with self.assertRaises(aws_iam.AwsIamError):
            # Not offered: the claim does not include billing-admins.
            aws_iam.select_role('billing-rw')
        with self.assertRaises(aws_iam.AwsIamError):
            aws_iam.select_role('nope')
        self.assertEqual(aws_iam.selected_role()['id'], 'billing-ro')


class TestRegionAndSessionName(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.assertEqual(aws_iam.region_for(RDS_HOST), 'eu-central-1')
        self.assertEqual(aws_iam.region_for(
            'x.cluster-ro-abc.us-gov-west-1.rds.amazonaws.com'),
            'us-gov-west-1')
        self.assertEqual(aws_iam.region_for('db.internal',
                                            {'region': 'eu-west-3'}),
                         'eu-west-3')
        with self.assertRaises(aws_iam.AwsIamError):
            aws_iam.region_for('db.internal')
        with patch.object(config, 'AWS_IAM_DEFAULT_REGION', 'us-east-2'):
            self.assertEqual(aws_iam.region_for('db.internal'), 'us-east-2')
        self.assertEqual(aws_iam.session_name('j doe/x@y.z'),
                         'j-doe-x@y.z')
        self.assertEqual(len(aws_iam.session_name('a' * 100)), 64)


class TestPasswordProviderSignsWithTheSelectedRole(_AwsTestCase,
                                                   BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        provider = aws_iam.AwsIamPassword(
            aws_iam.SESSION_ROLE_NAME, RDS_HOST, 5432, 'app_ro',
            {'sslmode': 'verify-full'})
        with self.assertRaises(aws_iam.AwsIamError):
            provider.get()  # nothing selected yet
        aws_iam.select_role('billing-ro')
        with patch.object(aws_iam, 'generate_rds_token',
                          return_value='rds-token') as sign:
            self.assertEqual(provider.get(), 'rds-token')
            self.assertEqual(provider.get(), 'rds-token')
            sign.assert_called_once()
            args = sign.call_args.args
            # The role's db_user replaces the server's user name.
            self.assertEqual(args[1:], (RDS_HOST, 5432, 'jdoe_ro',
                                        'eu-central-1'))
            self.assertEqual(provider.db_user(), 'jdoe_ro')
            self.assertEqual(args[0]['aws_access_key_id'], 'ASIAEXAMPLE')
            provider.invalidate()
            provider.get()
            self.assertEqual(sign.call_count, 2)


class TestPasswordProviderNeedsSsl(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        for sslmode in (None, 'disable', 'allow', 'prefer'):
            provider = aws_iam.AwsIamPassword(
                aws_iam.PINNED_ROLE_PREFIX + 'shared', RDS_HOST, 5432,
                'app', {'sslmode': sslmode} if sslmode else {})
            with self.subTest(sslmode):
                with self.assertRaises(aws_iam.AwsIamError):
                    provider.get()


class TestPinnedRoleIsUsedRegardlessOfSelection(_AwsTestCase,
                                                BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        provider = aws_iam.AwsIamPassword(
            aws_iam.PINNED_ROLE_PREFIX + 'shared', RDS_HOST, 5432, 'app',
            {'sslmode': 'require'})
        self.assertEqual(provider.role()['id'], 'shared')
        with patch.object(aws_iam, 'generate_rds_token',
                          return_value='t'):
            self.assertEqual(provider.get(), 't')


class TestPasswordExecNamesIncludeAwsChoices(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        choices = passexec.get_server_passexec_choices()
        self.assertEqual(choices[0], 'vault')
        values = [c['value'] for c in choices[1:]]
        self.assertEqual(values, ['__aws_iam__', '__aws_iam__:billing-ro',
                                  '__aws_iam__:billing-rw',
                                  '__aws_iam__:shared'])
        for name in ['vault', '__aws_iam__', '__aws_iam__:shared']:
            self.assertEqual(
                passexec.normalise_passexec_name(name, False), name)
        for name in ['__aws_iam__:nope', '__aws_iam__x', 'other']:
            with self.assertRaises(ValueError):
                passexec.normalise_passexec_name(name, False)
        with patch.object(config, 'AWS_IAM_ENABLED', False):
            self.assertEqual(passexec.get_server_passexec_choices(),
                             ['vault'])
            with self.assertRaises(ValueError):
                passexec.normalise_passexec_name('__aws_iam__', False)


class TestBuildPasswordExecReturnsAwsProvider(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        server = SimpleNamespace(
            id=7, user_id=1, shared=False, host=RDS_HOST, port=5432,
            username='app_ro', maintenance_db='postgres',
            passexec_name='__aws_iam__', passexec_expiration=None,
            passexec_cmd=None, connection_params={'sslmode': 'require'})
        with patch.object(passexec, 'current_user', self.user):
            provider = passexec.build_passexec(server)
        self.assertIsInstance(provider, aws_iam.AwsIamPassword)
        self.assertEqual(provider.username, 'app_ro')
        self.assertIsNone(provider.pinned_role_id)


class TestInvalidDbUserTemplateIsRefused(_AwsTestCase,
                                         BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        self.assertIsNone(aws_iam.find_role('bad-db-user'))
        role = aws_iam.find_role('billing-rw')
        self.assertEqual(aws_iam.role_db_user(role, 'jdoe@x.y'), 'app_rw')
        self.assertIsNone(aws_iam.role_db_user(aws_iam.find_role('shared'),
                                               'jdoe'))


class TestSessionRoleOnly(_AwsTestCase, BaseTestGenerator):
    """With AWS_IAM_SESSION_ROLE_ONLY, servers can only follow the session's
    role, and a role saved on a server earlier is used as the session's."""
    scenarios = [('default', dict())]

    def runTest(self):
        with patch.object(config, 'AWS_IAM_SESSION_ROLE_ONLY', True):
            choices = passexec.get_server_passexec_choices()
            self.assertEqual([c['value'] for c in choices[1:]],
                             ['__aws_iam__'])
            self.assertEqual(choices[1]['label'], 'AWS IAM (session role)')
            with self.assertRaises(ValueError):
                passexec.normalise_passexec_name('__aws_iam__:shared', False)
            self.assertEqual(
                passexec.normalise_passexec_name('__aws_iam__', False),
                '__aws_iam__')
            provider = aws_iam.AwsIamPassword(
                aws_iam.PINNED_ROLE_PREFIX + 'shared', RDS_HOST, 5432,
                'app', {'sslmode': 'require'})
            self.assertIsNone(provider.pinned_role_id)
            aws_iam.select_role('billing-ro')
            self.assertEqual(provider.role()['id'], 'billing-ro')


class TestRoleSwitchCanBeDisallowed(_AwsTestCase, BaseTestGenerator):
    scenarios = [('default', dict())]

    def runTest(self):
        with patch.object(config, 'AWS_IAM_ALLOW_ROLE_SWITCH', False):
            aws_iam.select_role('billing-ro')
            # Choosing the same role again (e.g. to renew) is fine.
            aws_iam.select_role('billing-ro')
            with self.assertRaises(aws_iam.AwsIamError) as e:
                aws_iam.select_role('shared')
            self.assertIn('Log out', str(e.exception))
        self.assertEqual(aws_iam.selected_role()['id'], 'billing-ro')


class TestDbUserFollowsTheSessionRole(_AwsTestCase, BaseTestGenerator):
    """ServerManager.user is the role's db_user while the session's role
    has one, and the server's own user name otherwise."""
    scenarios = [('default', dict())]

    def runTest(self):
        from pgadmin.utils.driver.psycopg3.server_manager import \
            ServerManager
        manager = ServerManager.__new__(ServerManager)
        manager.user = 'server_user'
        manager.passexec = aws_iam.AwsIamPassword(
            aws_iam.SESSION_ROLE_NAME, RDS_HOST, 5432, 'server_user',
            {'sslmode': 'require'})
        # No role chosen yet.
        self.assertEqual(manager.user, 'server_user')
        aws_iam.select_role('billing-ro')
        self.assertEqual(manager.user, 'jdoe_ro')
        self.assertEqual(manager.configured_user, 'server_user')
        with patch.object(aws_iam, 'release_selected_role_connections'):
            aws_iam.select_role('shared')
        # The shared role has no db_user: the server's user applies.
        self.assertEqual(manager.user, 'server_user')
        manager.passexec = None
        self.assertEqual(manager.user, 'server_user')
