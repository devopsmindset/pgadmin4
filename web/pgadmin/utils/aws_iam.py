##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""AWS IAM database authentication with the pgAdmin user's own identity.

The identity token of the pgAdmin login (the WEBSERVER_JWT_HEADER token
kept by pgadmin.utils.jwt_identity, or the OAuth2 ID token) is exchanged
with STS AssumeRoleWithWebIdentity for temporary credentials of one of the
roles in AWS_IAM_ROLES, and those credentials sign RDS IAM authentication
tokens. pgAdmin needs no AWS credentials of its own: STS decides, from the
role's trust policy, whether the user may use a role, and the role's
permissions decide which database users it can sign for.

Servers use this through their password exec setting, which offers
built-in values besides the administrator's commands:

  __aws_iam__            the role chosen for the session (role selector)
  __aws_iam__:<role id>  always that role (not offered with
                         AWS_IAM_SESSION_ROLE_ONLY, where every server uses
                         the session's role)

A role may name the database user it connects as ('db_user'), which then
replaces the server's user name, so that one server entry is used read-only
or read-write depending on the role chosen for the session.

Temporary credentials and tokens are kept in memory only.
"""

import re
import threading
import time

from flask import current_app, session
from flask_babel import gettext
from flask_security import current_user

import config
from pgadmin.utils import jwt_identity

SESSION_ROLE_NAME = '__aws_iam__'
PINNED_ROLE_PREFIX = SESSION_ROLE_NAME + ':'
SESSION_KEY = 'aws_iam_role'

SECURE_SSLMODES = ('require', 'verify-ca', 'verify-full')

# Credentials are renewed this long before they expire.
_CREDENTIALS_RENEW_MARGIN_SECONDS = 300
# A role STS refused is not asked for again for this long.
_REFUSAL_CACHE_SECONDS = 60

_ROLE_ARN_RE = re.compile(
    r'^arn:aws(-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$')
_ROLE_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
_RDS_HOST_REGION_RE = re.compile(
    r'\.([a-z]{2}(?:-[a-z]+)+-\d+)\.rds\.amazonaws\.com(?:\.cn)?\.?$')
_SESSION_NAME_BAD_CHARS = re.compile(r'[^\w+=,.@-]')


class AwsIamError(Exception):
    """An error to show to the user. It never contains a token or
    credentials."""


##########################################################################
# Configuration
##########################################################################

def _iter_role_entries():
    """Yield (role or None, reason) for each AWS_IAM_ROLES entry."""
    seen = set()
    for entry in getattr(config, 'AWS_IAM_ROLES', None) or []:
        if not isinstance(entry, dict):
            yield None, 'entries must be dicts'
            continue
        role_id, arn = entry.get('id'), entry.get('arn')
        if not isinstance(role_id, str) or not _ROLE_ID_RE.match(role_id):
            yield None, 'invalid id {0!r}'.format(role_id)
            continue
        if role_id in seen:
            yield None, 'duplicate id {0!r}'.format(role_id)
            continue
        if not isinstance(arn, str) or not _ROLE_ARN_RE.match(arn):
            yield None, 'invalid arn for {0!r}'.format(role_id)
            continue
        claim_values = entry.get('claim_values')
        if isinstance(claim_values, str):
            claim_values = [claim_values]
        claim_values = [v for v in (claim_values or [])
                        if isinstance(v, str) and v]
        db_user = entry.get('db_user') or None
        if db_user is not None and not _valid_db_user_template(db_user):
            yield None, 'invalid db_user for {0!r}'.format(role_id)
            continue
        seen.add(role_id)
        yield {
            'id': role_id,
            'arn': arn,
            'account': arn.split(':')[4],
            'name': arn.split('/')[-1],
            'label': entry.get('label') or role_id,
            'description': entry.get('description') or '',
            'region': entry.get('region') or None,
            'claim_values': claim_values,
            'db_user': db_user,
        }, None


def _format_db_user(template, username):
    username = username or ''
    return template.format(username=username,
                           local_username=username.split('@')[0])


def _valid_db_user_template(template):
    if not isinstance(template, str) or not template.strip():
        return False
    try:
        return bool(_format_db_user(template, 'user@example.com'))
    except (KeyError, IndexError, ValueError):
        return False


def role_db_user(role, username):
    """The database user a role connects as, or None when it uses the
    server's own user name. 'db_user' may contain {username} (the pgAdmin
    user name) and {local_username} (the part before '@')."""
    if not role or not role.get('db_user'):
        return None
    return _format_db_user(role['db_user'], username)


def configured_roles():
    return [role for role, reason in _iter_role_entries() if role]


def check_config(logger):
    """Log configuration problems once, at startup."""
    if not getattr(config, 'AWS_IAM_ENABLED', False):
        return
    for role, reason in _iter_role_entries():
        if reason:
            logger.error('Ignoring an AWS_IAM_ROLES entry: %s', reason)
    if not configured_roles():
        logger.error('AWS_IAM_ENABLED is set, but AWS_IAM_ROLES has no '
                     'usable role.')
    if any(r['claim_values'] for r in configured_roles()) and \
            not getattr(config, 'AWS_IAM_ROLE_CLAIM', None):
        logger.warning('AWS_IAM_ROLES has claim_values, but '
                       'AWS_IAM_ROLE_CLAIM is not set, so they are ignored.')


def is_enabled():
    return bool(config.SERVER_MODE and
                getattr(config, 'AWS_IAM_ENABLED', False) and
                configured_roles())


def find_role(role_id):
    for role in configured_roles():
        if role['id'] == role_id:
            return role
    return None


def session_role_only():
    """With AWS_IAM_SESSION_ROLE_ONLY, every AWS IAM server uses the role
    chosen for the session; servers cannot name a role of their own."""
    return bool(getattr(config, 'AWS_IAM_SESSION_ROLE_ONLY', True))


def role_switch_allowed():
    return bool(getattr(config, 'AWS_IAM_ALLOW_ROLE_SWITCH', True))


def is_builtin_name(name):
    return isinstance(name, str) and (
        name == SESSION_ROLE_NAME or name.startswith(PINNED_ROLE_PREFIX))


def is_valid_builtin_name(name):
    """True when a stored built-in value can be used. In session-role-only
    mode, a value naming a role (saved before the mode was turned on) is
    used as the session role."""
    if name == SESSION_ROLE_NAME:
        return True
    if not is_builtin_name(name):
        return False
    return session_role_only() or \
        find_role(name[len(PINNED_ROLE_PREFIX):]) is not None


def is_selectable_builtin_name(name):
    """True when a built-in value may be saved on a server now."""
    if session_role_only():
        return name == SESSION_ROLE_NAME
    return is_valid_builtin_name(name)


def builtin_password_providers():
    """[{'value', 'label'}] offered as password exec choices."""
    if not is_enabled():
        return []
    choices = [{'value': SESSION_ROLE_NAME,
                'label': gettext('AWS IAM (session role)')}]
    if session_role_only():
        return choices
    for role in configured_roles():
        choices.append({'value': PINNED_ROLE_PREFIX + role['id'],
                        'label': gettext('AWS IAM: {0}').format(
                            role['label'])})
    return choices


##########################################################################
# The user's web identity and role credentials
##########################################################################

def web_identity():
    """(token, claims) of the current user's login, or raise AwsIamError."""
    if not current_user or not current_user.is_authenticated:
        raise AwsIamError(gettext('You are not logged in.'))
    held = jwt_identity.current_token(current_user.username)
    if held:
        return held
    token = session.get('oauth2_token')
    if isinstance(token, dict) and isinstance(token.get('id_token'), str):
        claims = token.get('userinfo')
        claims = dict(claims) if isinstance(claims, dict) else {}
        exp = claims.get('exp')
        if not isinstance(exp, (int, float)) or exp - 30 > time.time():
            return token['id_token'], claims
    raise AwsIamError(gettext(
        'Your login token has expired or is not available. Reload the page, '
        'or log out and in again.'))


def _claim_values(claims):
    name = getattr(config, 'AWS_IAM_ROLE_CLAIM', None)
    if not name:
        return None
    value = claims.get(name)
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple)):
        return {v for v in value if isinstance(v, str)}
    return set()


def candidate_roles(claims):
    """The configured roles whose claim_values the token satisfies."""
    values = _claim_values(claims)
    return [role for role in configured_roles()
            if not role['claim_values'] or values is None or
            values.intersection(role['claim_values'])]


_clients_lock = threading.Lock()
_sts_clients = {}


def _sts_client():
    region = getattr(config, 'AWS_IAM_STS_REGION', None) or \
        getattr(config, 'AWS_IAM_DEFAULT_REGION', None)
    with _clients_lock:
        client = _sts_clients.get(region)
        if client is None:
            # Deferred: boto3 is heavy, and only needed when this is used.
            import boto3
            from botocore import UNSIGNED
            from botocore.config import Config
            kwargs = {'config': Config(
                # AssumeRoleWithWebIdentity is not signed: the web
                # identity token is the credential. pgAdmin's own AWS
                # credentials, if any, are never used.
                signature_version=UNSIGNED,
                connect_timeout=5, read_timeout=10,
                retries={'max_attempts': 3, 'mode': 'standard'})}
            if region:
                kwargs['region_name'] = region
            else:
                kwargs['region_name'] = 'us-east-1'
            client = boto3.session.Session().client('sts', **kwargs)
            _sts_clients[region] = client
        return client


def session_name(username):
    name = _SESSION_NAME_BAD_CHARS.sub('-', username or 'pgadmin')[:64]
    return name if len(name) >= 2 else 'pgadmin-' + name


def _duration():
    try:
        seconds = int(getattr(config, 'AWS_IAM_SESSION_DURATION', 3600))
    except (TypeError, ValueError):
        seconds = 3600
    return max(900, min(seconds, 43200))


_STS_ERRORS = {
    'AccessDenied': 'Your login is not allowed to assume this role.',
    'InvalidIdentityToken': 'AWS did not accept your login token.',
    'ExpiredTokenException': 'Your login token has expired. Reload the '
                             'page, or log out and in again.',
    'IDPRejectedClaim': 'AWS rejected a claim in your login token.',
    'IDPCommunicationError': 'AWS could not reach the identity provider. '
                             'Try again later.',
}


def _assume(role, token, username):
    from botocore.exceptions import BotoCoreError, ClientError
    client = _sts_client()
    duration = _duration()
    for attempt in range(2):
        try:
            return client.assume_role_with_web_identity(
                RoleArn=role['arn'], RoleSessionName=session_name(username),
                WebIdentityToken=token, DurationSeconds=duration)
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            message = e.response.get('Error', {}).get('Message', '')
            if attempt == 0 and code == 'ValidationError' and \
                    'DurationSeconds' in message and duration > 3600:
                # Longer than the role's maximum session duration.
                duration = 3600
                continue
            current_app.logger.info(
                'AWS IAM: STS refused role %s for %s: %s', role['arn'],
                username, code or type(e).__name__)
            raise AwsIamError(gettext(_STS_ERRORS.get(
                code, 'AWS refused the role ({0}).'.format(code or
                                                           'error'))))
        except BotoCoreError as e:
            current_app.logger.warning(
                'AWS IAM: could not reach STS: %s', type(e).__name__)
            raise AwsIamError(gettext('AWS STS could not be reached.'))


_credentials_lock = threading.Lock()
_credentials = {}
_key_locks = {}


def _lock_for(key):
    with _credentials_lock:
        return _key_locks.setdefault(key, threading.Lock())


def role_credentials(role):
    """Temporary credentials for role, assumed with the current user's
    login token and kept for this session until shortly before they
    expire. Raises AwsIamError."""
    token, claims = web_identity()
    username = current_user.username
    key = (getattr(session, 'sid', None), role['id'])
    with _lock_for(key):
        now = time.time()
        held = _credentials.get(key)
        if held and held['username'] == username:
            if held.get('error') and \
                    now - held['at'] < _REFUSAL_CACHE_SECONDS:
                raise AwsIamError(held['error'])
            if not held.get('error') and \
                    held['expires'] - _CREDENTIALS_RENEW_MARGIN_SECONDS > now:
                return held['credentials']
        try:
            response = _assume(role, token, username)
        except AwsIamError as e:
            _credentials[key] = {'username': username, 'error': str(e),
                                 'at': now}
            raise
        c = response['Credentials']
        credentials = {
            'aws_access_key_id': c['AccessKeyId'],
            'aws_secret_access_key': c['SecretAccessKey'],
            'aws_session_token': c['SessionToken'],
        }
        _credentials[key] = {
            'username': username, 'credentials': credentials, 'at': now,
            'expires': c['Expiration'].timestamp(),
            'assumed_arn': response.get('AssumedRoleUser', {}).get('Arn'),
        }
        return credentials


def credentials_info(role):
    """{'expires', 'assumed_arn'} for role in this session, or None."""
    held = _credentials.get((getattr(session, 'sid', None), role['id']))
    if not held or held.get('error') or \
            current_user.username != held['username']:
        return None
    return {'expires': held['expires'], 'assumed_arn': held['assumed_arn']}


def forget_session():
    sid = getattr(session, 'sid', None)
    with _credentials_lock:
        for key in [k for k in _credentials if k[0] == sid]:
            _credentials.pop(key, None)


def available_roles():
    """[(role, error or None)] for the roles offered to the current user.
    With AWS_IAM_PROBE_ROLES, error says why STS refused a role."""
    _token, claims = web_identity()
    result = []
    for role in candidate_roles(claims):
        error = None
        if getattr(config, 'AWS_IAM_PROBE_ROLES', True):
            try:
                role_credentials(role)
            except AwsIamError as e:
                error = str(e)
        result.append((role, error))
    return result


##########################################################################
# The selected role
##########################################################################

def selected_role():
    role_id = session.get(SESSION_KEY)
    return find_role(role_id) if role_id else None


def select_role(role_id):
    """Make role_id the session's role, after checking it is offered to the
    user and that STS lets the user assume it. Connections that follow the
    selected role are closed when it changes."""
    previous = session.get(SESSION_KEY)
    if previous and previous != role_id and not role_switch_allowed():
        raise AwsIamError(gettext(
            'The AWS role is chosen once per session. Log out and in again '
            'to use another role.'))
    role = find_role(role_id)
    _token, claims = web_identity()
    if role is None or role not in candidate_roles(claims):
        raise AwsIamError(gettext('That role is not available to you.'))
    role_credentials(role)
    session[SESSION_KEY] = role['id']
    if previous and previous != role['id']:
        release_selected_role_connections()
    return role


def auto_select_role():
    """Select the only usable role, if there is exactly one. Returns the
    selected role or None."""
    role = selected_role()
    if role:
        return role
    try:
        usable = [r for r, error in available_roles() if error is None]
    except AwsIamError:
        return None
    if len(usable) == 1:
        session[SESSION_KEY] = usable[0]['id']
        return usable[0]
    return None


def selection_required():
    """True when the main window must not open until a role is chosen."""
    return is_enabled() and \
        bool(getattr(config, 'AWS_IAM_REQUIRE_ROLE', True)) and \
        auto_select_role() is None


def release_selected_role_connections():
    """Close this session's connections that use the selected role, so
    that they reconnect as the new one."""
    from pgadmin.utils.driver import get_driver
    driver = get_driver(config.PG_DEFAULT_DRIVER)
    managers = getattr(driver, 'managers', {}).get(
        getattr(session, 'sid', None), {})
    for manager in list(managers.values()):
        provider = getattr(manager, 'passexec', None)
        if isinstance(provider, AwsIamPassword) and \
                provider.pinned_role_id is None:
            provider.invalidate()
            try:
                manager.release()
            except Exception as e:
                current_app.logger.warning(
                    'AWS IAM: could not close the connections of server '
                    '%s: %s', getattr(manager, 'sid', '?'), e)


##########################################################################
# RDS tokens
##########################################################################

def region_for(host, role=None):
    match = _RDS_HOST_REGION_RE.search((host or '').lower())
    if match:
        return match.group(1)
    region = (role or {}).get('region') or \
        getattr(config, 'AWS_IAM_DEFAULT_REGION', None)
    if not region:
        raise AwsIamError(gettext(
            'The AWS region of {0} cannot be worked out. Set a region on the '
            'role or in AWS_IAM_DEFAULT_REGION.').format(host))
    return region


def generate_rds_token(credentials, host, port, username, region):
    # Deferred: boto3 is heavy, and only needed when this is used.
    import boto3
    client = boto3.session.Session(region_name=region,
                                   **credentials).client('rds')
    # A local SigV4 signature: no call is made to AWS.
    return client.generate_db_auth_token(
        DBHostname=host, Port=int(port or 5432), DBUsername=username,
        Region=region)


def connect_error_message(manager, errmsg):
    """For a server using AWS IAM authentication, the connection error to
    show instead of a password prompt (which cannot help: the password is
    an IAM token), with a hint saying which database user and role were
    used. None for any other server."""
    provider = getattr(manager, 'passexec', None)
    if not isinstance(provider, AwsIamPassword):
        return None
    try:
        role = provider.role()
    except (AwsIamError, RuntimeError):
        # No role: the error already says so.
        return errmsg
    db_user = role_db_user(role, current_user.username) or provider.username
    hint = gettext(
        'AWS IAM authentication tried to connect as the database user "{0}" '
        'with the AWS role "{1}" ({2}). Check that this database user '
        'exists and is granted rds_iam, and that the role is allowed '
        'rds-db:connect as it.').format(db_user, role['label'], role['arn'])
    return '{0}\n\n{1}'.format(errmsg, hint) if errmsg else hint


class AwsIamPassword:
    """Takes the place of a password exec command for a server
    (ServerManager.passexec): get() returns an RDS IAM token for the
    server's host, port and database user, signed with the credentials of
    the user's role."""

    def __init__(self, name, host, port, username, connection_params=None):
        self.name = name
        self.pinned_role_id = name[len(PINNED_ROLE_PREFIX):] \
            if name.startswith(PINNED_ROLE_PREFIX) and \
            not session_role_only() else None
        self.host = host
        self.port = port
        self.username = username
        self.sslmode = (connection_params or {}).get('sslmode')
        self.lock = threading.Lock()
        self._token = None
        self._token_key = None
        self._token_at = 0.0

    def role(self):
        if self.pinned_role_id:
            role = find_role(self.pinned_role_id)
            if role is None:
                raise AwsIamError(gettext(
                    'The AWS role of this server is no longer configured.'))
            return role
        role = selected_role()
        if role is None:
            raise AwsIamError(gettext(
                'No AWS role is chosen for this session. Choose one from '
                'the user menu (AWS role).'))
        return role

    def invalidate(self):
        with self.lock:
            self._token = None
            self._token_key = None

    def db_user(self):
        """The database user the role connects as instead of the server's
        user name, or None. ServerManager.user asks this for every new
        connection, so a role switch changes the user too. Outside a
        request, or without a usable role, the server's user applies."""
        try:
            return role_db_user(self.role(), current_user.username)
        except (AwsIamError, RuntimeError, AttributeError):
            return None

    def get(self):
        if not self.host:
            raise AwsIamError(gettext(
                'AWS IAM authentication needs the server host name.'))
        if self.sslmode not in SECURE_SSLMODES:
            raise AwsIamError(gettext(
                'AWS IAM authentication needs SSL: set the SSL mode of the '
                'server to require, verify-ca or verify-full.'))
        role = self.role()
        username = role_db_user(role, current_user.username) or \
            self.username
        if not username:
            raise AwsIamError(gettext(
                'AWS IAM authentication needs the database user name.'))
        region = region_for(self.host, role)
        key = (current_user.username, role['id'], region, username)
        reuse = getattr(config, 'AWS_IAM_RDS_TOKEN_REUSE_SECONDS', 600)
        with self.lock:
            now = time.monotonic()
            if self._token and self._token_key == key and \
                    now - self._token_at < min(reuse, 840):
                return self._token
            credentials = role_credentials(role)
            token = generate_rds_token(credentials, self.host, self.port,
                                       username, region)
            self._token, self._token_key, self._token_at = token, key, now
            return token
