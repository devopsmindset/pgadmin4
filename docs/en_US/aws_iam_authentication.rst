.. _aws_iam_authentication:

*****************************************************
`AWS IAM Database Authentication`:index:
*****************************************************

In Server mode, pgAdmin can connect to Amazon RDS and Aurora PostgreSQL
databases with `IAM database authentication
<https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html>`_,
using **each user's own AWS identity**. pgAdmin itself needs no AWS
credentials:

1. The user logs in to pgAdmin through a proxy that passes a signed identity
   token (JWT) in a request header (see :ref:`webserver`), or through OAuth2.
2. pgAdmin exchanges that token with AWS STS ``AssumeRoleWithWebIdentity``
   for temporary credentials of an IAM role the user picks.
3. Those credentials sign a short-lived RDS authentication token, which is
   sent as the password of each new database connection.

What each user can reach is therefore decided by AWS: the trust policy of
each role says whose tokens may assume it, and its permissions say which
database users (``rds-db:connect``) it can sign for.

Prerequisites
*************

* The token issuer is registered in IAM as an OpenID Connect identity
  provider, with the token's audience in its client ID list. The issuer must
  publish ``/.well-known/openid-configuration`` and its signing keys.
* For each role users may pick, a trust policy that allows
  ``sts:AssumeRoleWithWebIdentity`` from that provider, with conditions on
  the token claims (for example ``<issuer>:aud``, ``<issuer>:sub`` or
  ``<issuer>:amr``), and a permission policy that allows ``rds-db:connect``
  on the database users the role may use.
* IAM database authentication enabled on the instance or cluster, and the
  database users granted the ``rds_iam`` role.
* Network access from pgAdmin to the regional STS endpoint, the token
  issuer, and the databases. RDS tokens are signed locally, so the RDS API
  is not called.

Identity from a proxy token
***************************

Set ``AUTHENTICATION_SOURCES = ['webserver']`` and ``WEBSERVER_JWT_HEADER`` to
the header holding the token. The token's signature (keys from
``WEBSERVER_JWT_JWKS_URL``, or discovered from the issuer), issuer, audience
and expiry are checked at login and again on every request: a token for a
different user logs the session out. A ``Bearer`` prefix is accepted, so the
token can come in the ``Authorization`` header from an identity-aware proxy
such as Ory Oathkeeper.

.. csv-table::
   :header: "**Parameter**", "**Description**"
   :class: longtable
   :widths: 35, 55

   "WEBSERVER_JWT_HEADER", "The request header that holds the token, e.g.
   *Authorization* or *Cf-Access-Jwt-Assertion*. Setting it enables this
   mode."
   "WEBSERVER_JWT_ISSUER", "The required *iss* claim."
   "WEBSERVER_JWT_AUDIENCE", "Accepted *aud* values. Empty skips the check,
   which is not recommended."
   "WEBSERVER_JWT_JWKS_URL", "Where to fetch the signing keys. When *None*,
   they are discovered from the issuer."
   "WEBSERVER_JWT_ALGORITHMS", "Accepted signing algorithms. *none* is never
   accepted."
   "WEBSERVER_JWT_USERNAME_CLAIM", "The claim that names the pgAdmin user."
   "WEBSERVER_JWT_USERNAME_SUFFIX", "Appended to the user name when it has no
   '@', e.g. *@example.com*."
   "WEBSERVER_JWT_DENY_USERNAMES", "User names that are refused, such as the
   subject a proxy uses for anonymous requests."

Roles and the role selector
***************************

.. csv-table::
   :header: "**Parameter**", "**Description**"
   :class: longtable
   :widths: 35, 55

   "AWS_IAM_ENABLED", "Enables AWS IAM database authentication."
   "AWS_IAM_ROLES", "The roles users may pick: a list of dicts with *id*,
   *arn*, and optionally *label*, *description*, *region* and
   *claim_values*."
   "AWS_IAM_ROLE_CLAIM", "A token claim (string or list) whose values gate the
   roles that have *claim_values*, e.g. a groups claim."
   "AWS_IAM_PROBE_ROLES", "Only offer a role when STS lets the user's token
   assume it. The reason STS refused is shown in the selector."
   "AWS_IAM_REQUIRE_ROLE", "Ask for a role before the main window opens.
   With a single usable role, it is selected automatically."
   "AWS_IAM_SESSION_DURATION", "The requested role session length in
   seconds."
   "AWS_IAM_STS_REGION, AWS_IAM_DEFAULT_REGION", "The STS endpoint region,
   and the database region when the role and the RDS host name do not say."

After login, a user with several usable roles chooses one in the role
selector, which also shows the account, the role name and when the current
credentials expire. It is reachable at any time from the *AWS role* entry of
the user menu; switching roles closes the connections that use the selected
role, so that they reconnect as the new one.

Configuring a server
********************

On the *Advanced* tab of the server dialog, set *Password exec command* to:

* *AWS IAM (selected role)* to connect as the role chosen in the selector,
  or
* *AWS IAM: <role>* to always use that role, for example for a server that
  should only ever be used read-only.

Set the *Username* to the database user the token is signed for, and the
*SSL mode* to *require*, *verify-ca* or *verify-full*: pgAdmin refuses to send
an IAM token over a connection without SSL. Tokens are generated for each new
connection and reused for up to ``AWS_IAM_RDS_TOKEN_REUSE_SECONDS``.

Example
*******

A proxy that passes an issuer-signed token in the ``Authorization`` header,
with group names in the *amr* claim:

.. code-block:: python

    AUTHENTICATION_SOURCES = ['webserver']
    WEBSERVER_JWT_HEADER = 'Authorization'
    WEBSERVER_JWT_ISSUER = 'https://token-issuer.example.com'
    WEBSERVER_JWT_AUDIENCE = ['pgadmin']
    WEBSERVER_JWT_USERNAME_CLAIM = 'common_name'
    WEBSERVER_JWT_USERNAME_SUFFIX = '@example.com'

    AWS_IAM_ENABLED = True
    AWS_IAM_ROLE_CLAIM = 'amr'
    AWS_IAM_DEFAULT_REGION = 'eu-central-1'
    AWS_IAM_ROLES = [
        {'id': 'billing-ro', 'label': 'Billing (read only)',
         'arn': 'arn:aws:iam::111111111111:role/billing-db-ro',
         'claim_values': ['billing-developers']},
        {'id': 'billing-rw', 'label': 'Billing (read/write)',
         'arn': 'arn:aws:iam::111111111111:role/billing-db-rw',
         'claim_values': ['billing-admins']},
    ]
