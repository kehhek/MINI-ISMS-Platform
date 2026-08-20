from collections import defaultdict
from functools import wraps
from io import StringIO
import csv
import hashlib
import json
import os
from datetime import datetime, timedelta

import pyotp
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, session, abort
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename

from app import db
from app.storage import get_storage_service, validate_upload, validate_video_upload
from app.models import (
    Tenant, Asset, Risk, Policy, WorkInstruction, SecurityAwarenessCampaign, AwarenessAssignment, Control, Finding, CorrectiveAction, Evidence, User, UserGroup, UserGroupMembership, AuditEvent, Role, ApprovalMatrix, ApprovalRecord
)

main = Blueprint('main', __name__)

FAILED_LOGIN_ATTEMPTS = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def get_tenant_scope(model):
    if hasattr(model, 'tenant_id'):
        return model.tenant_id == current_user.tenant_id
    return True


def require_roles(*allowed_roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to continue.')
                return redirect(url_for('main.login'))
            user_role = current_user.role.name if current_user.role else 'user'
            if user_role not in allowed_roles and user_role != 'admin':
                flash('You do not have permission to access this page.')
                return redirect(url_for('main.index'))
            return func(*args, **kwargs)
        return wrapped
    return decorator


def _signature_payload(user, entity_type, entity_id, action, before_value=None, after_value=None):
    before_text = '' if before_value is None else str(before_value)
    after_text = '' if after_value is None else str(after_value)
    stamp = f'{user.id}:{user.tenant_id}:{entity_type}:{entity_id}:{action}:{before_text}:{after_text}:{datetime.utcnow().isoformat()}'
    return hashlib.sha256(stamp.encode('utf-8')).hexdigest()


def log_audit_event(user, entity_type, entity_id, action, before_value=None, after_value=None, signed_change=None):
    if user is None:
        return
    payload = _signature_payload(user, entity_type, entity_id, action, before_value, after_value)
    event = AuditEvent(
        tenant_id=user.tenant_id,
        user_id=user.id,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        before_value=str(before_value) if before_value is not None else None,
        after_value=str(after_value) if after_value is not None else None,
        ip_address=request.remote_addr if request else None,
        signature_hash=payload,
        signed_change=signed_change or json.dumps({'before': before_value, 'after': after_value, 'action': action}, default=str),
    )
    db.session.add(event)
    db.session.commit()


@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))


@main.route('/overview')
@login_required
def overview():
    total_assets = Asset.query.filter_by(tenant_id=current_user.tenant_id).count()
    total_risks = Risk.query.filter_by(tenant_id=current_user.tenant_id).count()
    total_controls = Control.query.filter_by(tenant_id=current_user.tenant_id).count()
    total_findings = Finding.query.filter_by(tenant_id=current_user.tenant_id).count()
    total_evidence = Evidence.query.filter_by(tenant_id=current_user.tenant_id).count()

    return render_template(
        'overview.html',
        total_assets=total_assets,
        total_risks=total_risks,
        total_controls=total_controls,
        total_findings=total_findings,
        total_evidence=total_evidence,
    )


@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        now = datetime.utcnow()
        attempts = FAILED_LOGIN_ATTEMPTS.get(request.remote_addr, [])
        attempts = [ts for ts in attempts if ts > now - timedelta(seconds=LOCKOUT_SECONDS)]
        FAILED_LOGIN_ATTEMPTS[request.remote_addr] = attempts

        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            return (render_template('login.html', locked_out=True), 429)

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if user.mfa_enabled and user.mfa_secret:
                session['pending_mfa_user_id'] = user.id
                FAILED_LOGIN_ATTEMPTS.pop(request.remote_addr, None)
                flash('Multi-factor authentication required.')
                return redirect(url_for('main.mfa_verify'))

            FAILED_LOGIN_ATTEMPTS.pop(request.remote_addr, None)
            login_user(user)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            log_audit_event(user, 'user', user.id, 'login')
            flash('Welcome back.')
            return redirect(url_for('main.dashboard'))

        attempts.append(now)
        FAILED_LOGIN_ATTEMPTS[request.remote_addr] = attempts
        flash('Invalid email or password.')

    return render_template('login.html', locked_out=False)


@main.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    user_id = session.get('pending_mfa_user_id')
    user = User.query.get(user_id) if user_id else None
    if not user or not user.mfa_enabled or not user.mfa_secret:
        session.pop('pending_mfa_user_id', None)
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code, valid_window=1):
            session.pop('pending_mfa_user_id', None)
            login_user(user)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            log_audit_event(user, 'user', user.id, 'login_mfa')
            flash('Welcome back.')
            return redirect(url_for('main.dashboard'))
        flash('Invalid MFA code.')

    return render_template('mfa_verify.html', user=user)


@main.route('/settings/mfa', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if request.method == 'POST':
        if not current_user.mfa_secret:
            current_user.mfa_secret = pyotp.random_base32()
        if request.form.get('enable') == '1':
            current_user.mfa_enabled = True
            db.session.commit()
            flash('Multi-factor authentication enabled.')
        elif request.form.get('disable') == '1':
            current_user.mfa_enabled = False
            current_user.mfa_secret = None
            db.session.commit()
            flash('Multi-factor authentication disabled.')
        return redirect(url_for('main.dashboard'))

    secret = current_user.mfa_secret or pyotp.random_base32()
    if not current_user.mfa_secret:
        current_user.mfa_secret = secret
        db.session.commit()

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name='Invaryant ISMS Platform',
    )
    return render_template('mfa_setup.html', secret=secret, otp_uri=otp_uri, enabled=current_user.mfa_enabled)


@main.route('/logout')
@login_required
def logout():
    log_audit_event(current_user, 'user', current_user.id, 'logout')
    session.pop('pending_mfa_user_id', None)
    logout_user()
    return redirect(url_for('main.login'))


# --- Users ---
@main.route('/profile')
@login_required
def profile():
    user = User.query.filter_by(id=current_user.id, tenant_id=current_user.tenant_id).first_or_404()
    groups = user.groups.all() if hasattr(user.groups, 'all') else []
    return render_template('user_profile.html', user=user, groups=groups)


@main.route('/users/<int:user_id>')
@login_required
def user_detail(user_id):
    user = User.query.filter_by(id=user_id, tenant_id=current_user.tenant_id).first_or_404()
    if current_user.id != user.id and not (current_user.role and current_user.role.name in {'admin', 'security_manager'}):
        flash('You do not have permission to view that profile.')
        return redirect(url_for('main.profile'))
    groups = user.groups.all() if hasattr(user.groups, 'all') else []
    return render_template('user_profile.html', user=user, groups=groups, is_detail_view=True)


@main.route('/users')
@login_required
@require_roles('admin', 'security_manager')
def users_list():
    users = User.query.filter_by(tenant_id=current_user.tenant_id).order_by(User.full_name.asc()).all()
    return render_template('users_list.html', users=users)


@main.route('/users/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def user_new():
    roles = Role.query.filter_by(tenant_id=current_user.tenant_id).all()
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role_id = request.form.get('role_id')
        is_active = request.form.get('is_active') == '1'

        if not full_name or not email or not password:
            flash('Name, email, and password are required.')
            return render_template('user_form.html', roles=roles)

        if User.query.filter_by(email=email).first():
            flash('A user with that email already exists.')
            return render_template('user_form.html', roles=roles)

        selected_role = Role.query.filter_by(id=role_id, tenant_id=current_user.tenant_id).first()
        if not selected_role:
            selected_role = Role.query.filter_by(tenant_id=current_user.tenant_id, name='user').first()

        user = User(
            tenant_id=current_user.tenant_id,
            email=email,
            full_name=full_name,
            role_id=selected_role.id if selected_role else 1,
            is_active=is_active,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        log_audit_event(current_user, 'user', user.id, 'created', before_value=None, after_value=user.email)
        flash('User added successfully.')
        return redirect(url_for('main.users_list'))

    return render_template('user_form.html', roles=roles)


@main.route('/users/<int:user_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def user_delete(user_id):
    user = User.query.filter_by(id=user_id, tenant_id=current_user.tenant_id).first_or_404()

    if user.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('main.users_list'))

    if ApprovalRecord.query.filter_by(approver_id=user.id).first():
        flash('This user has approval records and cannot be deleted until those records are reassigned or removed.')
        return redirect(url_for('main.users_list'))

    UserGroupMembership.query.filter_by(user_id=user.id).delete()
    AwarenessAssignment.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()

    log_audit_event(current_user, 'user', user.id, 'deleted', before_value=user.email, after_value=None)
    flash('User deleted successfully.')
    return redirect(url_for('main.users_list'))


@main.route('/user-groups')
@login_required
@require_roles('admin', 'security_manager')
def user_groups_list():
    groups = UserGroup.query.filter_by(tenant_id=current_user.tenant_id).order_by(UserGroup.name.asc()).all()
    return render_template('user_groups_list.html', groups=groups)


@main.route('/user-groups/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def user_group_new():
    users = User.query.filter_by(tenant_id=current_user.tenant_id).order_by(User.full_name.asc()).all()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        member_ids = request.form.getlist('member_ids')

        if not name:
            flash('Group name is required.')
            return render_template('user_group_form.html', users=users)

        if UserGroup.query.filter_by(tenant_id=current_user.tenant_id, name=name).first():
            flash('A group with that name already exists for this tenant.')
            return render_template('user_group_form.html', users=users)

        group = UserGroup(
            tenant_id=current_user.tenant_id,
            name=name,
            description=description,
        )
        db.session.add(group)
        db.session.flush()

        selected_users = User.query.filter(User.id.in_(member_ids), User.tenant_id == current_user.tenant_id).all()
        group.users.extend(selected_users)
        db.session.commit()

        log_audit_event(current_user, 'user_group', group.id, 'created', before_value=None, after_value=group.name)
        flash('User group created successfully.')
        return redirect(url_for('main.user_groups_list'))

    return render_template('user_group_form.html', users=users)


# --- Assets ---
@main.route('/assets')
@login_required
def assets_list():
    assets = Asset.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('assets_list.html', assets=assets)


@main.route('/assets/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def asset_new():
    if request.method == 'POST':
        asset = Asset(
            tenant_id=current_user.tenant_id,
            name=request.form['name'],
            asset_type=request.form['asset_type'],
            owner=request.form['owner'],
            classification=request.form['classification'],
            description=request.form['description'],
            created_by_user_id=current_user.id,
        )
        db.session.add(asset)
        db.session.commit()
        log_audit_event(current_user, 'asset', asset.id, 'created', before_value=None, after_value=str(asset.name))
        flash('Asset added successfully.')
        return redirect(url_for('main.assets_list'))
    return render_template('asset_form.html')


@main.route('/assets/<int:asset_id>')
@login_required
def asset_detail(asset_id):
    asset = Asset.query.filter_by(id=asset_id, tenant_id=current_user.tenant_id).first_or_404()
    return render_template('asset_detail.html', asset=asset)


@main.route('/assets/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def asset_edit(asset_id):
    asset = Asset.query.filter_by(id=asset_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        previous = {
            'name': asset.name,
            'asset_type': asset.asset_type,
            'owner': asset.owner,
            'classification': asset.classification,
            'location': asset.location,
            'description': asset.description,
        }
        asset.name = request.form['name']
        asset.asset_type = request.form.get('asset_type')
        asset.owner = request.form.get('owner')
        asset.classification = request.form.get('classification')
        asset.location = request.form.get('location')
        asset.description = request.form.get('description')
        db.session.commit()
        log_audit_event(current_user, 'asset', asset.id, 'updated', before_value=str(previous), after_value=str({
            'name': asset.name,
            'asset_type': asset.asset_type,
            'owner': asset.owner,
            'classification': asset.classification,
            'location': asset.location,
            'description': asset.description,
        }))
        flash('Asset updated successfully.')
        return redirect(url_for('main.asset_detail', asset_id=asset.id))
    return render_template('asset_form.html', asset=asset)


@main.route('/assets/<int:asset_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def asset_delete(asset_id):
    asset = Asset.query.filter_by(id=asset_id, tenant_id=current_user.tenant_id).first_or_404()
    db.session.delete(asset)
    db.session.commit()
    log_audit_event(current_user, 'asset', asset_id, 'deleted', before_value=asset.name, after_value=None)
    flash('Asset deleted successfully.')
    return redirect(url_for('main.assets_list'))


# --- Risks ---
@main.route('/risks')
@login_required
def risks_list():
    risks = Risk.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('risks_list.html', risks=risks)


@main.route('/risks/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def risk_new():
    if request.method == 'POST':
        asset_id = request.form.get('asset_id') or None
        risk = Risk(
            tenant_id=current_user.tenant_id,
            title=request.form['title'],
            description=request.form['description'],
            asset_id=asset_id,
            likelihood=int(request.form['likelihood']),
            impact=int(request.form['impact']),
            owner=request.form['owner'],
            status=request.form.get('status', 'Open'),
            created_by_user_id=current_user.id,
        )
        db.session.add(risk)
        db.session.commit()
        log_audit_event(current_user, 'risk', risk.id, 'created', before_value=None, after_value=risk.title)
        flash('Risk added successfully.')
        return redirect(url_for('main.risks_list'))
    assets = Asset.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('risk_form.html', assets=assets)


@main.route('/risks/<int:risk_id>')
@login_required
def risk_detail(risk_id):
    risk = Risk.query.filter_by(id=risk_id, tenant_id=current_user.tenant_id).first_or_404()
    return render_template('risk_detail.html', risk=risk)


@main.route('/risks/<int:risk_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def risk_edit(risk_id):
    risk = Risk.query.filter_by(id=risk_id, tenant_id=current_user.tenant_id).first_or_404()
    assets = Asset.query.filter_by(tenant_id=current_user.tenant_id).all()

    if request.method == 'POST':
        previous = {
            'title': risk.title,
            'description': risk.description,
            'asset_id': risk.asset_id,
            'likelihood': risk.likelihood,
            'impact': risk.impact,
            'owner': risk.owner,
            'status': risk.status,
        }
        risk.title = request.form['title']
        risk.description = request.form.get('description')
        risk.asset_id = request.form.get('asset_id') or None
        risk.likelihood = int(request.form['likelihood']) if request.form.get('likelihood') else None
        risk.impact = int(request.form['impact']) if request.form.get('impact') else None
        risk.owner = request.form.get('owner')
        risk.status = request.form.get('status', risk.status or 'Open')
        db.session.commit()
        log_audit_event(current_user, 'risk', risk.id, 'updated', before_value=str(previous), after_value=str({
            'title': risk.title,
            'description': risk.description,
            'asset_id': risk.asset_id,
            'likelihood': risk.likelihood,
            'impact': risk.impact,
            'owner': risk.owner,
            'status': risk.status,
        }))
        flash('Risk updated successfully.')
        return redirect(url_for('main.risk_detail', risk_id=risk.id))

    return render_template('risk_form.html', risk=risk, assets=assets)


@main.route('/risks/<int:risk_id>/approve', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def risk_approve(risk_id):
    risk = Risk.query.filter_by(id=risk_id, tenant_id=current_user.tenant_id).first_or_404()
    approval_matrix = ApprovalMatrix.query.filter_by(tenant_id=current_user.tenant_id, entity_type='risk', is_active=True).first()
    if approval_matrix and current_user.role and current_user.role.name != approval_matrix.required_role and current_user.role.name != 'admin':
        flash(f'Only {approval_matrix.required_role} users can approve this record.')
        return redirect(url_for('main.risk_detail', risk_id=risk.id))

    if request.method == 'POST':
        decision = request.form.get('decision', 'approve').lower()
        reason = request.form.get('reason', '')
        approved_at = datetime.utcnow()
        old_status = risk.approval_status
        old_reason = risk.approval_reason
        risk.approval_status = 'Approved' if decision == 'approve' else 'Rejected'
        risk.approval_reason = reason
        risk.approved_by_user_id = current_user.id
        risk.approved_at = approved_at
        risk.signature_hash = hashlib.sha256(f'{risk.id}:{current_user.id}:{decision}:{reason}:{approved_at.isoformat()}'.encode('utf-8')).hexdigest()
        if decision == 'approve':
            risk.status = 'Approved'
            risk.locked_at = approved_at
        else:
            risk.locked_at = approved_at

        approval_record = ApprovalRecord(
            tenant_id=current_user.tenant_id,
            entity_type='risk',
            entity_id=risk.id,
            action='approval',
            approver_id=current_user.id,
            reason=reason,
            decision=decision,
            signature_hash=risk.signature_hash,
        )
        db.session.add(approval_record)
        db.session.commit()
        log_audit_event(
            current_user,
            'risk',
            risk.id,
            'approved' if decision == 'approve' else 'rejected',
            before_value={'approval_status': old_status, 'approval_reason': old_reason},
            after_value={'approval_status': risk.approval_status, 'approval_reason': reason, 'signature_hash': risk.signature_hash},
            signed_change=f'{decision}:{reason}',
        )
        flash('Risk approval recorded and signed.')
        return redirect(url_for('main.risk_detail', risk_id=risk.id))

    return render_template('risk_approval.html', risk=risk)


@main.route('/risks/<int:risk_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def risk_delete(risk_id):
    risk = Risk.query.filter_by(id=risk_id, tenant_id=current_user.tenant_id).first_or_404()
    risk.signature_hash = hashlib.sha256(f'{risk.id}:{current_user.id}:delete:{datetime.utcnow().isoformat()}'.encode('utf-8')).hexdigest()
    db.session.delete(risk)
    db.session.commit()
    log_audit_event(current_user, 'risk', risk_id, 'deleted', before_value=risk.title, after_value=None, signed_change='delete')
    flash('Risk deleted successfully.')
    return redirect(url_for('main.risks_list'))


# --- Policies ---
@main.route('/policies')
@login_required
def policies_list():
    policies = Policy.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('policies_list.html', policies=policies)


@main.route('/policies/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def policy_new():
    if request.method == 'POST':
        review_date = request.form.get('review_date')
        file = request.files.get('file')
        policy = Policy(
            tenant_id=current_user.tenant_id,
            title=request.form['title'],
            version=request.form['version'],
            owner=request.form['owner'],
            status=request.form['status'],
            review_date=datetime.strptime(review_date, '%Y-%m-%d') if review_date else None,
            content_summary=request.form['content_summary'],
            created_by_user_id=current_user.id,
        )

        if file and file.filename:
            try:
                filename = validate_upload(file)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('main.policy_new'))
            storage = get_storage_service(current_app)
            filepath = storage.save(file, filename)
            policy.document_filename = filename
            policy.document_path = filepath
            policy.mime_type = file.mimetype or 'application/pdf'
            policy.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        db.session.add(policy)
        db.session.commit()
        log_audit_event(current_user, 'policy', policy.id, 'created', before_value=None, after_value=policy.title)
        flash('Policy added successfully.')
        return redirect(url_for('main.policies_list'))
    return render_template('policy_form.html')


@main.route('/policies/<int:policy_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def policy_edit(policy_id):
    policy = Policy.query.filter_by(id=policy_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        previous = {
            'title': policy.title,
            'version': policy.version,
            'owner': policy.owner,
            'status': policy.status,
            'review_date': policy.review_date,
            'content_summary': policy.content_summary,
            'document_filename': policy.document_filename,
            'document_path': policy.document_path,
        }
        policy.title = request.form['title']
        policy.version = request.form.get('version')
        policy.owner = request.form.get('owner')
        policy.status = request.form.get('status')
        review_date = request.form.get('review_date')
        policy.review_date = datetime.strptime(review_date, '%Y-%m-%d') if review_date else None
        policy.content_summary = request.form.get('content_summary')

        file = request.files.get('file')
        if file and file.filename:
            try:
                filename = validate_upload(file)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('main.policy_edit', policy_id=policy.id))
            storage = get_storage_service(current_app)
            filepath = storage.save(file, filename)
            policy.document_filename = filename
            policy.document_path = filepath
            policy.mime_type = file.mimetype or 'application/pdf'
            policy.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        db.session.commit()
        log_audit_event(current_user, 'policy', policy.id, 'updated', before_value=str(previous), after_value=str({
            'title': policy.title,
            'version': policy.version,
            'owner': policy.owner,
            'status': policy.status,
            'review_date': policy.review_date,
            'content_summary': policy.content_summary,
            'document_filename': policy.document_filename,
            'document_path': policy.document_path,
        }))
        flash('Policy updated successfully.')
        return redirect(url_for('main.policies_list'))
    return render_template('policy_form.html', policy=policy)


@main.route('/policies/<int:policy_id>/download')
@login_required
def policy_download(policy_id):
    policy = Policy.query.filter_by(id=policy_id, tenant_id=current_user.tenant_id).first_or_404()
    if not policy.document_path or not os.path.exists(policy.document_path):
        flash('No policy document is attached.')
        return redirect(url_for('main.policies_list'))
    return send_file(policy.document_path, as_attachment=True, download_name=policy.document_filename or 'policy.pdf', mimetype=policy.mime_type or 'application/pdf')


# --- Work Instructions ---
@main.route('/work-instructions')
@login_required
def work_instructions_list():
    work_instructions = WorkInstruction.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('work_instructions_list.html', work_instructions=work_instructions)


@main.route('/work-instructions/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def work_instruction_new():
    if request.method == 'POST':
        review_date = request.form.get('review_date')
        file = request.files.get('file')
        instruction = WorkInstruction(
            tenant_id=current_user.tenant_id,
            title=request.form['title'],
            version=request.form.get('version', '1.0'),
            owner=request.form.get('owner'),
            status=request.form.get('status', 'Draft'),
            review_date=datetime.strptime(review_date, '%Y-%m-%d') if review_date else None,
            steps=request.form.get('steps'),
            created_by_user_id=current_user.id,
        )

        if file and file.filename:
            try:
                filename = validate_upload(file)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('main.work_instruction_new'))
            storage = get_storage_service(current_app)
            filepath = storage.save(file, filename)
            instruction.document_filename = filename
            instruction.document_path = filepath
            instruction.mime_type = file.mimetype or 'application/pdf'
            instruction.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        db.session.add(instruction)
        db.session.commit()
        log_audit_event(current_user, 'work_instruction', instruction.id, 'created', before_value=None, after_value=instruction.title)
        flash('Work instruction added successfully.')
        return redirect(url_for('main.work_instructions_list'))
    return render_template('work_instruction_form.html')


@main.route('/work-instructions/<int:instruction_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def work_instruction_edit(instruction_id):
    instruction = WorkInstruction.query.filter_by(id=instruction_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        previous = {
            'title': instruction.title,
            'version': instruction.version,
            'owner': instruction.owner,
            'status': instruction.status,
            'review_date': instruction.review_date,
            'steps': instruction.steps,
            'document_filename': instruction.document_filename,
        }
        instruction.title = request.form['title']
        instruction.version = request.form.get('version', instruction.version)
        instruction.owner = request.form.get('owner')
        instruction.status = request.form.get('status', instruction.status)
        review_date = request.form.get('review_date')
        instruction.review_date = datetime.strptime(review_date, '%Y-%m-%d') if review_date else None
        instruction.steps = request.form.get('steps')

        file = request.files.get('file')
        if file and file.filename:
            try:
                filename = validate_upload(file)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('main.work_instruction_edit', instruction_id=instruction.id))
            storage = get_storage_service(current_app)
            filepath = storage.save(file, filename)
            instruction.document_filename = filename
            instruction.document_path = filepath
            instruction.mime_type = file.mimetype or 'application/pdf'
            instruction.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        db.session.commit()
        log_audit_event(current_user, 'work_instruction', instruction.id, 'updated', before_value=str(previous), after_value=str({
            'title': instruction.title,
            'version': instruction.version,
            'owner': instruction.owner,
            'status': instruction.status,
            'review_date': instruction.review_date,
            'steps': instruction.steps,
            'document_filename': instruction.document_filename,
        }))
        flash('Work instruction updated successfully.')
        return redirect(url_for('main.work_instructions_list'))
    return render_template('work_instruction_form.html', instruction=instruction)


@main.route('/work-instructions/<int:instruction_id>/download')
@login_required
def work_instruction_download(instruction_id):
    instruction = WorkInstruction.query.filter_by(id=instruction_id, tenant_id=current_user.tenant_id).first_or_404()
    if not instruction.document_path or not os.path.exists(instruction.document_path):
        flash('No work instruction document is attached.')
        return redirect(url_for('main.work_instructions_list'))
    return send_file(instruction.document_path, as_attachment=True, download_name=instruction.document_filename or 'work-instruction.pdf', mimetype=instruction.mime_type or 'application/pdf')


@main.route('/work-instructions/<int:instruction_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def work_instruction_delete(instruction_id):
    instruction = WorkInstruction.query.filter_by(id=instruction_id, tenant_id=current_user.tenant_id).first_or_404()
    db.session.delete(instruction)
    db.session.commit()
    log_audit_event(current_user, 'work_instruction', instruction_id, 'deleted', before_value=instruction.title, after_value=None)
    flash('Work instruction deleted successfully.')
    return redirect(url_for('main.work_instructions_list'))


# --- Security Awareness Training ---
@main.route('/security-awareness')
@login_required
def security_awareness_list():
    if current_user.role and current_user.role.name in {'admin', 'security_manager', 'auditor'}:
        campaigns = SecurityAwarenessCampaign.query.filter_by(tenant_id=current_user.tenant_id).order_by(SecurityAwarenessCampaign.created_at.desc()).all()
        assignments = AwarenessAssignment.query.filter_by(tenant_id=current_user.tenant_id).order_by(AwarenessAssignment.assigned_at.desc()).all()
        all_groups = UserGroup.query.filter_by(tenant_id=current_user.tenant_id).order_by(UserGroup.name.asc()).all()
    else:
        assignments = AwarenessAssignment.query.filter_by(user_id=current_user.id, tenant_id=current_user.tenant_id).order_by(AwarenessAssignment.assigned_at.desc()).all()
        campaigns = [assignment.campaign for assignment in assignments]
        all_groups = current_user.groups.order_by(UserGroup.name.asc()).all() if hasattr(current_user.groups, 'order_by') else list(current_user.groups)

    watched_assignments = [a for a in assignments if a.status == 'Completed']
    pending_assignments = [a for a in assignments if a.status in {'Assigned', 'Pending'}]
    in_progress_assignments = [a for a in assignments if a.status == 'In Progress']

    group_status_breakdown = []
    for group in all_groups:
        group_user_ids = [user.id for user in group.users.all()] if hasattr(group.users, 'all') else [member.id for member in group.users]
        group_assignments = [assignment for assignment in assignments if assignment.user_id in group_user_ids]
        group_status_breakdown.append({
            'group': group,
            'watched': sum(1 for assignment in group_assignments if assignment.status == 'Completed'),
            'pending': sum(1 for assignment in group_assignments if assignment.status in {'Assigned', 'Pending'}),
            'in_progress': sum(1 for assignment in group_assignments if assignment.status == 'In Progress'),
            'total': len(group_assignments),
        })

    return render_template(
        'security_awareness_list.html',
        campaigns=campaigns,
        assignments=assignments,
        watched_assignments=watched_assignments,
        pending_assignments=pending_assignments,
        in_progress_assignments=in_progress_assignments,
        group_status_breakdown=group_status_breakdown,
    )


@main.route('/security-awareness/video/<path:filename>')
@login_required
def security_awareness_video(filename):
    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(404)

    video_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)
    if not os.path.exists(video_path):
        abort(404)

    return send_file(video_path, mimetype='video/mp4')


@main.route('/security-awareness/generate', methods=['POST'])
@login_required
@require_roles('admin', 'security_manager')
def generate_monthly_security_awareness():
    title = request.form.get('title') or f"Security Awareness - {datetime.utcnow().strftime('%B %Y')}"
    month_label = request.form.get('month_label') or datetime.utcnow().strftime('%B %Y')
    video_title = request.form.get('video_title') or 'Monthly Security Awareness Briefing'
    description = request.form.get('description') or 'Monthly security awareness briefing covering phishing, password hygiene, and secure working practices.'
    video_url = request.form.get('video_url', '').strip()
    video_file = request.files.get('video_file')

    if video_file and video_file.filename:
        try:
            filename = validate_video_upload(video_file)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for('main.security_awareness_new'))

        storage = get_storage_service(current_app)
        saved_path = storage.save(video_file, filename)
        video_url = url_for('main.security_awareness_video', filename=os.path.basename(saved_path))
    elif not video_url:
        video_url = 'https://example.com/security-awareness/' + month_label.lower().replace(' ', '-') + '.mp4'

    due_date = request.form.get('due_date')
    due_date_obj = datetime.strptime(due_date, '%Y-%m-%d') if due_date else datetime.utcnow() + timedelta(days=30)

    campaign = SecurityAwarenessCampaign(
        tenant_id=current_user.tenant_id,
        title=title,
        month_label=month_label,
        video_title=video_title,
        description=description,
        video_url=video_url,
        status='Scheduled',
        due_date=due_date_obj,
        created_by_user_id=current_user.id,
    )
    db.session.add(campaign)
    db.session.commit()

    for user in User.query.filter_by(tenant_id=current_user.tenant_id, is_active=True).all():
        assignment = AwarenessAssignment(
            tenant_id=current_user.tenant_id,
            campaign_id=campaign.id,
            user_id=user.id,
            status='Assigned',
            assigned_at=datetime.utcnow(),
            sent_at=datetime.utcnow(),
        )
        db.session.add(assignment)

    db.session.commit()
    log_audit_event(current_user, 'security_awareness_campaign', campaign.id, 'generated', before_value=None, after_value=title)
    flash('Monthly security awareness campaign generated and assigned to users.')
    return redirect(url_for('main.security_awareness_list'))


@main.route('/security-awareness/<int:campaign_id>/complete', methods=['POST'])
@login_required
def complete_security_awareness(campaign_id):
    assignment = AwarenessAssignment.query.filter_by(id=campaign_id, user_id=current_user.id).first_or_404()
    assignment.status = 'Completed'
    assignment.watched_at = datetime.utcnow()
    assignment.completion_score = 100
    db.session.commit()
    log_audit_event(current_user, 'security_awareness_assignment', assignment.id, 'completed', before_value='Assigned', after_value='Completed')
    flash('Security awareness video marked as complete.')
    return redirect(url_for('main.security_awareness_list'))


@main.route('/security-awareness/<int:assignment_id>/mark-watched', methods=['POST'])
@login_required
def mark_security_awareness_watched(assignment_id):
    assignment = AwarenessAssignment.query.filter_by(id=assignment_id, user_id=current_user.id).first_or_404()
    previous_status = assignment.status
    assignment.status = 'Completed'
    assignment.watched_at = datetime.utcnow()
    assignment.completion_score = 100
    assignment.notes = (assignment.notes or '') + ' Video watched in browser.'
    db.session.commit()
    log_audit_event(current_user, 'security_awareness_assignment', assignment.id, 'browser_completed', before_value=previous_status, after_value='Completed')
    return {'status': 'completed', 'assignment_id': assignment.id, 'watched_at': assignment.watched_at.isoformat()}, 200


@main.route('/security-awareness/new', methods=['GET'])
@login_required
@require_roles('admin', 'security_manager')
def security_awareness_new():
    default_month = datetime.utcnow().strftime('%B %Y')
    return render_template('security_awareness_form.html', default_month=default_month)


# --- Controls ---
@main.route('/controls')
@login_required
def controls_list():
    controls = Control.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('controls_list.html', controls=controls)


@main.route('/controls/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def control_new():
    if request.method == 'POST':
        risk_id = request.form.get('risk_id') or None
        policy_id = request.form.get('policy_id') or None
        control = Control(
            tenant_id=current_user.tenant_id,
            control_id=request.form['control_id'],
            name=request.form['name'],
            description=request.form['description'],
            control_type=request.form['control_type'],
            implementation_status=request.form['implementation_status'],
            risk_id=risk_id,
            policy_id=policy_id,
            created_by_user_id=current_user.id,
        )
        db.session.add(control)
        db.session.commit()
        log_audit_event(current_user, 'control', control.id, 'created', before_value=None, after_value=control.name)
        flash('Control added successfully.')
        return redirect(url_for('main.controls_list'))
    risks = Risk.query.filter_by(tenant_id=current_user.tenant_id).all()
    policies = Policy.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('control_form.html', risks=risks, policies=policies)


@main.route('/controls/<int:control_id>')
@login_required
def control_detail(control_id):
    control = Control.query.filter_by(id=control_id, tenant_id=current_user.tenant_id).first_or_404()
    return render_template('control_detail.html', control=control)


@main.route('/controls/<int:control_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager')
def control_edit(control_id):
    control = Control.query.filter_by(id=control_id, tenant_id=current_user.tenant_id).first_or_404()
    risks = Risk.query.filter_by(tenant_id=current_user.tenant_id).all()
    policies = Policy.query.filter_by(tenant_id=current_user.tenant_id).all()

    if request.method == 'POST':
        previous = {
            'control_id': control.control_id,
            'name': control.name,
            'description': control.description,
            'control_type': control.control_type,
            'implementation_status': control.implementation_status,
            'risk_id': control.risk_id,
            'policy_id': control.policy_id,
        }
        control.control_id = request.form.get('control_id')
        control.name = request.form['name']
        control.description = request.form.get('description')
        control.control_type = request.form.get('control_type')
        control.implementation_status = request.form.get('implementation_status')
        control.risk_id = request.form.get('risk_id') or None
        control.policy_id = request.form.get('policy_id') or None
        db.session.commit()
        log_audit_event(current_user, 'control', control.id, 'updated', before_value=str(previous), after_value=str({
            'control_id': control.control_id,
            'name': control.name,
            'description': control.description,
            'control_type': control.control_type,
            'implementation_status': control.implementation_status,
            'risk_id': control.risk_id,
            'policy_id': control.policy_id,
        }))
        flash('Control updated successfully.')
        return redirect(url_for('main.control_detail', control_id=control.id))

    return render_template('control_form.html', control=control, risks=risks, policies=policies)


@main.route('/controls/<int:control_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def control_delete(control_id):
    control = Control.query.filter_by(id=control_id, tenant_id=current_user.tenant_id).first_or_404()
    db.session.delete(control)
    db.session.commit()
    log_audit_event(current_user, 'control', control_id, 'deleted', before_value=control.name, after_value=None)
    flash('Control deleted successfully.')
    return redirect(url_for('main.controls_list'))


# --- Findings ---
@main.route('/findings')
@login_required
def findings_list():
    findings = Finding.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('findings_list.html', findings=findings)


@main.route('/findings/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def finding_new():
    if request.method == 'POST':
        control_id = request.form.get('control_id') or None
        finding = Finding(
            tenant_id=current_user.tenant_id,
            title=request.form['title'],
            description=request.form['description'],
            severity=request.form['severity'],
            status=request.form['status'],
            audit_name=request.form['audit_name'],
            identified_by=request.form['identified_by'],
            control_id=control_id,
            created_by_user_id=current_user.id,
        )
        db.session.add(finding)
        db.session.commit()
        log_audit_event(current_user, 'finding', finding.id, 'created', before_value=None, after_value=finding.title)
        flash('Finding added successfully.')
        return redirect(url_for('main.findings_list'))
    controls = Control.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('finding_form.html', controls=controls)


@main.route('/findings/<int:finding_id>')
@login_required
def finding_detail(finding_id):
    finding = Finding.query.filter_by(id=finding_id, tenant_id=current_user.tenant_id).first_or_404()
    from datetime import datetime as dt
    return render_template('finding_detail.html', finding=finding, now=dt.now())


@main.route('/findings/<int:finding_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def finding_edit(finding_id):
    finding = Finding.query.filter_by(id=finding_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        control_id = request.form.get('control_id') or None
        previous = {
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity,
            'status': finding.status,
            'audit_name': finding.audit_name,
            'identified_by': finding.identified_by,
            'control_id': finding.control_id,
        }
        finding.title = request.form['title']
        finding.description = request.form['description']
        finding.severity = request.form['severity']
        finding.status = request.form['status']
        finding.audit_name = request.form['audit_name']
        finding.identified_by = request.form['identified_by']
        finding.control_id = control_id
        db.session.commit()
        log_audit_event(current_user, 'finding', finding.id, 'updated', before_value=str(previous), after_value=str({
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity,
            'status': finding.status,
            'audit_name': finding.audit_name,
            'identified_by': finding.identified_by,
            'control_id': finding.control_id,
        }))
        flash('Finding updated successfully.')
        return redirect(url_for('main.finding_detail', finding_id=finding.id))
    controls = Control.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('finding_form.html', finding=finding, controls=controls)


@main.route('/findings/<int:finding_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def finding_delete(finding_id):
    finding = Finding.query.filter_by(id=finding_id, tenant_id=current_user.tenant_id).first_or_404()
    db.session.delete(finding)
    db.session.commit()
    log_audit_event(current_user, 'finding', finding_id, 'deleted', before_value=finding.title, after_value=None)
    flash('Finding deleted successfully.')
    return redirect(url_for('main.findings_list'))


# --- Corrective Actions ---
@main.route('/findings/<int:finding_id>/corrective-actions/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def corrective_action_new(finding_id):
    finding = Finding.query.filter_by(id=finding_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        due_date = request.form.get('due_date')
        completed_date = request.form.get('completed_date')
        action = CorrectiveAction(
            tenant_id=current_user.tenant_id,
            finding_id=finding_id,
            description=request.form['description'],
            owner=request.form['owner'],
            status=request.form['status'],
            due_date=datetime.strptime(due_date, '%Y-%m-%d') if due_date else None,
            completed_date=datetime.strptime(completed_date, '%Y-%m-%d') if completed_date else None,
            created_by_user_id=current_user.id,
        )
        db.session.add(action)
        db.session.commit()
        log_audit_event(current_user, 'corrective_action', action.id, 'created', before_value=None, after_value=action.description)
        flash('Corrective action added successfully.')
        return redirect(url_for('main.finding_detail', finding_id=finding_id))
    return render_template('action_form.html', finding=finding)


@main.route('/corrective-actions/<int:action_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def corrective_action_edit(action_id):
    action = CorrectiveAction.query.filter_by(id=action_id, tenant_id=current_user.tenant_id).first_or_404()
    if request.method == 'POST':
        due_date = request.form.get('due_date')
        completed_date = request.form.get('completed_date')
        action.description = request.form['description']
        action.owner = request.form['owner']
        action.status = request.form['status']
        action.due_date = datetime.strptime(due_date, '%Y-%m-%d') if due_date else None
        action.completed_date = datetime.strptime(completed_date, '%Y-%m-%d') if completed_date else None
        db.session.commit()
        log_audit_event(current_user, 'corrective_action', action.id, 'updated', before_value=None, after_value=action.description)
        flash('Corrective action updated successfully.')
        return redirect(url_for('main.finding_detail', finding_id=action.finding_id))
    return render_template('action_form.html', action=action)


@main.route('/corrective-actions/<int:action_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def corrective_action_delete(action_id):
    action = CorrectiveAction.query.filter_by(id=action_id, tenant_id=current_user.tenant_id).first_or_404()
    finding_id = action.finding_id
    db.session.delete(action)
    db.session.commit()
    log_audit_event(current_user, 'corrective_action', action_id, 'deleted', before_value=action.description, after_value=None)
    flash('Corrective action deleted successfully.')
    return redirect(url_for('main.finding_detail', finding_id=finding_id))


# --- Evidence ---
@main.route('/evidence')
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_list():
    evidence = Evidence.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('evidence_list.html', evidence=evidence)


@main.route('/evidence/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_new():
    if request.method == 'POST':
        file = request.files.get('file')
        if file is None or not file.filename:
            flash('Please select a file to upload.')
            return redirect(url_for('main.evidence_new'))

        try:
            filename = validate_upload(file)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for('main.evidence_new'))

        storage = get_storage_service(current_app)
        filepath = storage.save(file, filename)

        control_id = request.form.get('control_id') or None
        finding_id = request.form.get('finding_id') or None

        evidence = Evidence(
            tenant_id=current_user.tenant_id,
            title=request.form['title'],
            filename=filename,
            file_path=filepath,
            description=request.form['description'],
            uploaded_by=request.form['uploaded_by'],
            uploaded_by_user_id=current_user.id,
            file_hash='sha256-placeholder',
            file_size=os.path.getsize(filepath) if os.path.exists(filepath) else 0,
            mime_type=file.mimetype,
            retention_policy='90 days',
            storage_provider=current_app.config.get('STORAGE_BACKEND', 'local'),
            control_id=control_id,
            finding_id=finding_id,
        )
        db.session.add(evidence)
        db.session.commit()
        log_audit_event(current_user, 'evidence', evidence.id, 'uploaded', before_value=None, after_value=evidence.filename)
        flash('Evidence uploaded successfully.')
        return redirect(url_for('main.evidence_list'))

    controls = Control.query.filter_by(tenant_id=current_user.tenant_id).all()
    findings = Finding.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('evidence_form.html', controls=controls, findings=findings)


@main.route('/evidence/<int:evidence_id>')
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_detail(evidence_id):
    evidence = Evidence.query.filter_by(id=evidence_id, tenant_id=current_user.tenant_id).first_or_404()
    return render_template('evidence_detail.html', evidence=evidence)


@main.route('/evidence/<int:evidence_id>/file')
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_file(evidence_id):
    evidence = Evidence.query.filter_by(id=evidence_id, tenant_id=current_user.tenant_id).first_or_404()
    file_path = evidence.file_path
    if not file_path:
        abort(404)

    normalized_path = os.path.abspath(file_path)
    if not os.path.exists(normalized_path):
        abort(404)

    return send_file(normalized_path, as_attachment=False, mimetype=evidence.mime_type or 'application/octet-stream')


@main.route('/evidence/<int:evidence_id>/edit', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_edit(evidence_id):
    evidence = Evidence.query.filter_by(id=evidence_id, tenant_id=current_user.tenant_id).first_or_404()
    controls = Control.query.filter_by(tenant_id=current_user.tenant_id).all()
    findings = Finding.query.filter_by(tenant_id=current_user.tenant_id).all()

    if request.method == 'POST':
        previous = {
            'title': evidence.title,
            'uploaded_by': evidence.uploaded_by,
            'description': evidence.description,
            'control_id': evidence.control_id,
            'finding_id': evidence.finding_id,
        }
        evidence.title = request.form['title']
        evidence.uploaded_by = request.form.get('uploaded_by')
        evidence.description = request.form.get('description')
        evidence.control_id = request.form.get('control_id') or None
        evidence.finding_id = request.form.get('finding_id') or None

        file = request.files.get('file')
        if file and file.filename:
            try:
                filename = validate_upload(file)
            except ValueError as exc:
                flash(str(exc))
                return redirect(url_for('main.evidence_edit', evidence_id=evidence.id))
            storage = get_storage_service(current_app)
            filepath = storage.save(file, filename)
            evidence.filename = filename
            evidence.file_path = filepath
            evidence.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            evidence.mime_type = file.mimetype
            evidence.storage_provider = current_app.config.get('STORAGE_BACKEND', 'local')

        db.session.commit()
        log_audit_event(current_user, 'evidence', evidence.id, 'updated', before_value=str(previous), after_value=str({
            'title': evidence.title,
            'uploaded_by': evidence.uploaded_by,
            'description': evidence.description,
            'control_id': evidence.control_id,
            'finding_id': evidence.finding_id,
        }))
        flash('Evidence updated successfully.')
        return redirect(url_for('main.evidence_detail', evidence_id=evidence.id))

    return render_template('evidence_form.html', evidence=evidence, controls=controls, findings=findings)


@main.route('/evidence/<int:evidence_id>/delete', methods=['GET', 'POST'])
@login_required
@require_roles('admin')
def evidence_delete(evidence_id):
    evidence = Evidence.query.filter_by(id=evidence_id, tenant_id=current_user.tenant_id).first_or_404()
    db.session.delete(evidence)
    db.session.commit()
    log_audit_event(current_user, 'evidence', evidence_id, 'deleted', before_value=evidence.title, after_value=None)
    flash('Evidence deleted successfully.')
    return redirect(url_for('main.evidence_list'))


# --- Reports / Exports ---
@main.route('/reports')
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def reports_index():
    recent_events = AuditEvent.query.filter_by(tenant_id=current_user.tenant_id).order_by(AuditEvent.created_at.desc()).limit(5).all()
    return render_template('reports.html', recent_events=recent_events)


@main.route('/audit-trail')
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def audit_trail():
    events = AuditEvent.query.filter_by(tenant_id=current_user.tenant_id).order_by(AuditEvent.created_at.desc()).all()
    return render_template('audit_trail.html', events=events)


@main.route('/reports/risks.csv')
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def export_risks_csv():
    risks = Risk.query.filter_by(tenant_id=current_user.tenant_id).all()
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(['id', 'title', 'status', 'likelihood', 'impact', 'risk_score', 'owner'])
    for item in risks:
        writer.writerow([item.id, item.title, item.status, item.likelihood, item.impact, item.risk_score, item.owner])

    output = csv_buffer.getvalue().encode('utf-8')
    log_audit_event(current_user, 'report', None, 'exported_risks_csv')
    return send_file(
        __import__('io').BytesIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name='risks.csv',
    )


@main.route('/reports/audit-log.csv')
@login_required
@require_roles('admin', 'security_manager', 'auditor')
def export_audit_log_csv():
    events = AuditEvent.query.filter_by(tenant_id=current_user.tenant_id).order_by(AuditEvent.created_at.desc()).all()
    approvals = ApprovalRecord.query.filter_by(tenant_id=current_user.tenant_id).order_by(ApprovalRecord.approved_at.desc()).all()
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(['source', 'id', 'entity_type', 'entity_id', 'action', 'user_id', 'created_at', 'before_value', 'after_value', 'signature_hash', 'signed_change', 'ip_address', 'decision'])

    for item in events:
        writer.writerow([
            'audit_event',
            item.id,
            item.entity_type,
            item.entity_id,
            item.action,
            item.user_id,
            item.created_at,
            item.before_value,
            item.after_value,
            item.signature_hash,
            item.signed_change,
            item.ip_address,
            '',
        ])

    for item in approvals:
        writer.writerow([
            'approval_record',
            item.id,
            item.entity_type,
            item.entity_id,
            item.action,
            item.approver_id,
            item.approved_at,
            '',
            item.reason,
            item.signature_hash,
            item.reason,
            '',
            item.decision,
        ])

    output = csv_buffer.getvalue().encode('utf-8')
    log_audit_event(current_user, 'report', None, 'exported_audit_log_csv', before_value='Audit export request', after_value='CSV generated', signed_change='audit_export')
    return send_file(
        __import__('io').BytesIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name='audit-log.csv',
    )


# --- Dashboard ---
@main.route('/dashboard')
@login_required
def dashboard():
    total_controls = Control.query.filter_by(tenant_id=current_user.tenant_id).count()
    implemented = Control.query.filter_by(tenant_id=current_user.tenant_id, implementation_status='Implemented').count()
    control_implementation_pct = round((implemented / total_controls) * 100) if total_controls else 0

    open_findings_count = Finding.query.filter(Finding.tenant_id == current_user.tenant_id, Finding.status != 'Closed').count()

    overdue_actions = CorrectiveAction.query.filter(
        CorrectiveAction.tenant_id == current_user.tenant_id,
        CorrectiveAction.due_date < datetime.utcnow(),
        CorrectiveAction.status.notin_(['Completed', 'Verified'])
    ).order_by(CorrectiveAction.due_date.asc()).all()
    overdue_actions_count = len(overdue_actions)

    high_risk_count = 0
    for r in Risk.query.filter_by(tenant_id=current_user.tenant_id).all():
        if r.risk_score is not None and r.risk_score >= 15:
            high_risk_count += 1

    severity_counts = {
        'Critical': Finding.query.filter_by(tenant_id=current_user.tenant_id, severity='Critical').count(),
        'High': Finding.query.filter_by(tenant_id=current_user.tenant_id, severity='High').count(),
        'Medium': Finding.query.filter_by(tenant_id=current_user.tenant_id, severity='Medium').count(),
        'Low': Finding.query.filter_by(tenant_id=current_user.tenant_id, severity='Low').count(),
    }

    control_status_counts = {
        'Implemented': Control.query.filter_by(tenant_id=current_user.tenant_id, implementation_status='Implemented').count(),
        'Partially Implemented': Control.query.filter_by(tenant_id=current_user.tenant_id, implementation_status='Partially Implemented').count(),
        'Not Implemented': Control.query.filter_by(tenant_id=current_user.tenant_id, implementation_status='Not Implemented').count(),
    }

    risk_buckets = {'Low (1-7)': 0, 'Medium (8-14)': 0, 'High (15-25)': 0}
    for r in Risk.query.filter_by(tenant_id=current_user.tenant_id).all():
        if r.risk_score is None:
            continue
        if r.risk_score >= 15:
            risk_buckets['High (15-25)'] += 1
        elif r.risk_score >= 8:
            risk_buckets['Medium (8-14)'] += 1
        else:
            risk_buckets['Low (1-7)'] += 1

    return render_template('dashboard.html',
        control_implementation_pct=control_implementation_pct,
        open_findings_count=open_findings_count,
        overdue_actions=overdue_actions,
        overdue_actions_count=overdue_actions_count,
        high_risk_count=high_risk_count,
        severity_counts=severity_counts,
        control_status_counts=control_status_counts,
        risk_buckets=risk_buckets
    )