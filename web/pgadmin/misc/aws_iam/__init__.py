##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""The AWS role selector for AWS IAM database authentication (see
pgadmin.utils.aws_iam and AWS_IAM_* in config.py)."""

from datetime import datetime, timezone

from flask import abort, redirect, render_template, request, url_for
from flask_babel import gettext
from flask_security import current_user

from pgadmin.authenticate import get_logout_url
from pgadmin.user_login_check import pga_login_required
from pgadmin.utils import PgAdminModule, aws_iam
from pgadmin.utils.ajax import make_json_response

MODULE_NAME = 'aws_iam'


class AwsIamModule(PgAdminModule):
    def get_exposed_url_endpoints(self):
        return ['aws_iam.role', 'aws_iam.status']


blueprint = AwsIamModule(MODULE_NAME, __name__)


def _expiry_text(info):
    if not info:
        return None
    return datetime.fromtimestamp(info['expires'], timezone.utc).strftime(
        '%Y-%m-%d %H:%M UTC')


def _render(error=None, status=200):
    roles, identity_error = [], None
    try:
        roles = aws_iam.available_roles()
    except aws_iam.AwsIamError as e:
        identity_error = str(e)
    selected = aws_iam.selected_role()
    locked = bool(selected) and not aws_iam.role_switch_allowed()
    entries = []
    for role, refusal in roles:
        is_selected = bool(selected and selected['id'] == role['id'])
        entries.append({
            'id': role['id'],
            'label': role['label'],
            'description': role['description'],
            'account': role['account'],
            'name': role['name'],
            'db_user': aws_iam.role_db_user(role, current_user.username),
            'error': refusal,
            'selected': is_selected,
            'locked': locked and not is_selected,
            'expires': _expiry_text(aws_iam.credentials_info(role))
            if not refusal else None,
        })
    return render_template(
        'aws_iam/role.html',
        username=current_user.username,
        roles=entries,
        usable=sum(1 for e in entries if not e['error']),
        selected=selected,
        locked=locked,
        error=error or identity_error,
        browser_url=url_for('browser.index'),
        logout_url=get_logout_url(),
    ), status


@blueprint.route('/role', methods=['GET'], endpoint='role')
@pga_login_required
def role_page():
    if not aws_iam.is_enabled():
        abort(404)
    return _render()


@blueprint.route('/role', methods=['POST'], endpoint='select')
@pga_login_required
def role_select():
    if not aws_iam.is_enabled():
        abort(404)
    role_id = request.form.get('role_id', '')
    try:
        aws_iam.select_role(role_id)
    except aws_iam.AwsIamError as e:
        return _render(error=str(e), status=400)
    return redirect(url_for('browser.index'))


@blueprint.route('/status', methods=['GET'], endpoint='status')
@pga_login_required
def role_status():
    """The selected role and when its credentials expire."""
    if not aws_iam.is_enabled():
        return make_json_response(data={'enabled': False})
    role = aws_iam.selected_role()
    data = {'enabled': True, 'role': None}
    if role:
        info = aws_iam.credentials_info(role)
        data['role'] = {
            'id': role['id'], 'label': role['label'], 'arn': role['arn'],
            'account': role['account'],
            'assumed_arn': info['assumed_arn'] if info else None,
            'expires': info['expires'] if info else None,
        }
    return make_json_response(data=data)
