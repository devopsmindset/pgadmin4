##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""Verify the signed identity token (JWT) that the proxy in front of pgAdmin
passes in a request header (WEBSERVER_JWT_* in config.py), and keep the
latest verified token of each session in memory so that it can be exchanged
for cloud credentials (see pgadmin.utils.aws_iam).

Tokens are kept in this process only, never in the session store on disk:
the proxy sends a fresh one with every request, so a restart loses nothing.
pgAdmin runs a single worker process in server mode, which is what makes a
per-process store sufficient.
"""

import json
import threading
import time
import urllib.request

from flask import request, session

import config

try:
    # A dependency of Authlib, which pgAdmin already uses for OAuth2.
    from joserfc import jwt as _jwt
    from joserfc.errors import InvalidKeyIdError, JoseError
    from joserfc.jwk import KeySet
except ImportError:  # pragma: no cover - only very old Authlib releases
    _jwt = None

    class JoseError(Exception):
        pass

    class InvalidKeyIdError(JoseError):
        pass

# The key set is fetched again no more often than this when a token names an
# unknown key, so that tokens with made-up key ids cannot hammer the issuer.
_JWKS_MIN_REFETCH_SECONDS = 60
_HTTP_TIMEOUT_SECONDS = 10
_MAX_DOCUMENT_BYTES = 1024 * 1024
# A remembered token is treated as expired this many seconds early, so a
# token handed to STS does not expire on the way.
_TOKEN_EXPIRY_MARGIN_SECONDS = 30


class JWTIdentityError(Exception):
    """The token is missing, malformed, or failed verification."""


def jwt_mode_enabled():
    return bool(getattr(config, 'WEBSERVER_JWT_HEADER', None))


def _fetch_json(url):
    # An explicit User-Agent: some CDNs refuse Python's default one.
    req = urllib.request.Request(url, headers={
        'Accept': 'application/json',
        'User-Agent': 'pgAdmin4/{0}'.format(
            getattr(config, 'APP_VERSION', ''))})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as resp:
        body = resp.read(_MAX_DOCUMENT_BYTES + 1)
    if len(body) > _MAX_DOCUMENT_BYTES:
        raise JWTIdentityError('The document at {0} is too large.'.format(url))
    return json.loads(body.decode('utf-8'))


class _KeySetCache:
    """The issuer's signing keys, fetched on first use and refreshed after
    WEBSERVER_JWT_JWKS_CACHE_SECONDS, or early when a token names a key id
    that is not in the cached set."""

    def __init__(self):
        self._lock = threading.Lock()
        self._jwks_url = None
        self._keys = None
        self._fetched_at = 0.0

    def _resolve_jwks_url(self):
        if config.WEBSERVER_JWT_JWKS_URL:
            return config.WEBSERVER_JWT_JWKS_URL
        issuer = (config.WEBSERVER_JWT_ISSUER or '').rstrip('/')
        doc = _fetch_json(issuer + '/.well-known/openid-configuration')
        url = doc.get('jwks_uri') if isinstance(doc, dict) else None
        if not isinstance(url, str) or not url:
            raise JWTIdentityError(
                'The OpenID configuration of {0} has no jwks_uri.'.format(
                    issuer))
        return url

    def get(self, refetch=False):
        with self._lock:
            now = time.monotonic()
            age = now - self._fetched_at
            if self._keys is None or \
                    age >= config.WEBSERVER_JWT_JWKS_CACHE_SECONDS or \
                    (refetch and age >= _JWKS_MIN_REFETCH_SECONDS):
                url = self._jwks_url if self._keys is not None and \
                    not config.WEBSERVER_JWT_JWKS_URL else None
                url = url or self._resolve_jwks_url()
                self._keys = KeySet.import_key_set(_fetch_json(url))
                self._jwks_url = url
                self._fetched_at = now
            return self._keys

    def clear(self):
        with self._lock:
            self._keys = None
            self._jwks_url = None
            self._fetched_at = 0.0


_key_set = _KeySetCache()


def _audiences():
    aud = config.WEBSERVER_JWT_AUDIENCE
    if isinstance(aud, str):
        aud = [aud]
    return [a for a in (aud or []) if isinstance(a, str) and a]


def verify_token(token):
    """Return the claims of a valid token, or raise JWTIdentityError."""
    if _jwt is None:
        raise JWTIdentityError('Verifying JWTs needs the joserfc package.')
    if not config.WEBSERVER_JWT_ISSUER:
        raise JWTIdentityError('WEBSERVER_JWT_ISSUER is not configured.')
    if not isinstance(token, str) or token.count('.') != 2:
        raise JWTIdentityError('The token is not a JWT.')

    algorithms = [a for a in (config.WEBSERVER_JWT_ALGORITHMS or [])
                  if isinstance(a, str) and a.lower() != 'none']
    if not algorithms:
        raise JWTIdentityError('WEBSERVER_JWT_ALGORITHMS is empty.')

    options = {
        'iss': {'essential': True, 'value': config.WEBSERVER_JWT_ISSUER},
        'exp': {'essential': True},
    }
    audiences = _audiences()
    if audiences:
        options['aud'] = {'essential': True, 'values': audiences}
    registry = _jwt.JWTClaimsRegistry(
        leeway=int(config.WEBSERVER_JWT_LEEWAY or 0), **options)

    try:
        try:
            decoded = _jwt.decode(token, _key_set.get(),
                                  algorithms=algorithms)
        except InvalidKeyIdError:
            # The issuer has probably rotated its keys: fetch them again
            # (rate limited) and try once more.
            decoded = _jwt.decode(token, _key_set.get(refetch=True),
                                  algorithms=algorithms)
        registry.validate(decoded.claims)
    except JWTIdentityError:
        raise
    except JoseError as e:
        raise JWTIdentityError('The token failed verification ({0}).'.format(
            getattr(e, 'error', None) or type(e).__name__)) from None
    except (ValueError, TypeError) as e:
        raise JWTIdentityError('The token could not be decoded ({0}).'.format(
            type(e).__name__)) from None
    except OSError as e:
        raise JWTIdentityError(
            'The signing keys could not be fetched: {0}'.format(e)) from None
    return dict(decoded.claims)


def read_token_from_request():
    """The raw token from the configured header, without any 'Bearer '
    prefix, or None."""
    value = request.headers.get(config.WEBSERVER_JWT_HEADER)
    if not value:
        return None
    value = value.strip()
    if value[:7].lower() == 'bearer ':
        value = value[7:].strip()
    return value or None


def username_from_claims(claims):
    """The pgAdmin user name for verified claims, or None when the claim is
    missing or names a refused user."""
    value = claims.get(config.WEBSERVER_JWT_USERNAME_CLAIM or 'email')
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    denied = {d.lower() for d in (config.WEBSERVER_JWT_DENY_USERNAMES or [])
              if isinstance(d, str)}
    if value.lower() in denied:
        return None
    suffix = config.WEBSERVER_JWT_USERNAME_SUFFIX
    if suffix and '@' not in value:
        value += suffix
    return value


def identity_from_request():
    """Verify the token in the current request.

    Returns (username, claims, token), or None when the request carries no
    token. Raises JWTIdentityError when there is a token but it is invalid
    or does not name an acceptable user."""
    token = read_token_from_request()
    if token is None:
        return None
    claims = verify_token(token)
    username = username_from_claims(claims)
    if username is None:
        raise JWTIdentityError('The token does not name an acceptable user.')
    return username, claims, token


##########################################################################
# Latest verified token of each session
##########################################################################

_tokens_lock = threading.Lock()
_tokens = {}


def _session_key():
    return getattr(session, 'sid', None)


def remember_token(username, claims, token):
    """Keep the token for the current session, unless the one already kept
    for the same user lasts longer."""
    key = _session_key()
    exp = claims.get('exp')
    if key is None or not isinstance(exp, (int, float)):
        return
    with _tokens_lock:
        now = time.time()
        for k in [k for k, v in _tokens.items() if v['exp'] <= now]:
            del _tokens[k]
        held = _tokens.get(key)
        if held and held['username'] == username and held['exp'] >= exp:
            return
        _tokens[key] = {'username': username, 'claims': claims,
                        'token': token, 'exp': exp}


def current_token(username=None):
    """(token, claims) kept for the current session, if it is still valid
    and, when given, belongs to username."""
    key = _session_key()
    if key is None:
        return None
    with _tokens_lock:
        held = _tokens.get(key)
    if not held or held['exp'] - _TOKEN_EXPIRY_MARGIN_SECONDS <= time.time():
        return None
    if username is not None and held['username'] != username:
        return None
    return held['token'], held['claims']


def forget_token():
    key = _session_key()
    if key is not None:
        with _tokens_lock:
            _tokens.pop(key, None)
