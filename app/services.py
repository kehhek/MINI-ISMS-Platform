from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from flask import current_app
from flask_mail import Message
from werkzeug.utils import secure_filename

from app import db, mail
from app.models import (
    CorrectiveAction,
    Finding,
    PasswordResetToken,
    Risk,
    Role,
    Tenant,
    User,
)
from app.storage import get_storage_service, validate_upload


def get_or_create_tenant(tenant_name: Optional[str] = None, tenant_slug: Optional[str] = None):
    tenant = Tenant.query.order_by(Tenant.id.asc()).first()
    if tenant is not None:
        return tenant

    tenant = Tenant(
        name=tenant_name or os.getenv('TENANT_NAME', 'Default Tenant'),
        slug=tenant_slug or os.getenv('TENANT_SLUG', 'default-tenant'),
        status='active',
    )
    db.session.add(tenant)
    db.session.commit()
    return tenant


def get_or_create_role(tenant_id: int, role_name: str, description: str | None = None):
    role = Role.query.filter_by(tenant_id=tenant_id, name=role_name).first()
    if role is not None:
        return role

    role = Role(tenant_id=tenant_id, name=role_name, description=description or role_name)
    db.session.add(role)
    db.session.commit()
    return role


def register_user_account(full_name: str, email: str, password: str, tenant: Optional[Tenant] = None):
    normalized_name = (full_name or '').strip()
    normalized_email = (email or '').strip().lower()
    if not normalized_name or not normalized_email or not password:
        raise ValueError('Name, email, and password are required.')

    User.validate_password_strength(password)

    existing_user = User.query.filter_by(email=normalized_email).first()
    if existing_user is not None:
        raise ValueError('A user with that email already exists.')

    selected_tenant = tenant or get_or_create_tenant()
    role = get_or_create_role(selected_tenant.id, 'user', 'Standard user')

    user = User(
        tenant_id=selected_tenant.id,
        email=normalized_email,
        full_name=normalized_name,
        role_id=role.id,
        is_active=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def create_tenant_user(tenant_id: int, full_name: str, email: str, password: str, role_name: str = 'user', is_active: bool = True):
    normalized_name = (full_name or '').strip()
    normalized_email = (email or '').strip().lower()
    if not normalized_name or not normalized_email or not password:
        raise ValueError('Name, email, and password are required.')

    User.validate_password_strength(password)

    existing_user = User.query.filter_by(email=normalized_email).first()
    if existing_user is not None:
        raise ValueError('A user with that email already exists.')

    role = get_or_create_role(tenant_id, role_name, role_name)
    user = User(
        tenant_id=tenant_id,
        email=normalized_email,
        full_name=normalized_name,
        role_id=role.id,
        is_active=is_active,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def send_email(subject: str, recipients: list[str], body: str, html_body: str | None = None):
    if not recipients:
        return False

    mail_config = current_app.config
    if mail_config.get('MAIL_SUPPRESS_SEND'):
        print(f'Email suppressed: {subject} -> {recipients[0]}')
        print(body)
        return True

    msg = Message(subject=subject, recipients=recipients, body=body, html=html_body)
    sender = mail_config.get('MAIL_DEFAULT_SENDER')
    if sender:
        msg.sender = sender

    try:
        mail.send(msg)
        return True
    except Exception as exc:  # pragma: no cover - SMTP connectivity is environment dependent.
        print(f'Failed to send email via SMTP: {exc}')
        print(body)
        return False


def request_password_reset(email: str):
    normalized_email = (email or '').strip().lower()
    user = User.query.filter_by(email=normalized_email).first()
    if user is None:
        return None

    token_value = uuid.uuid4().hex
    reset_token = PasswordResetToken(
        user_id=user.id,
        token=token_value,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.session.add(reset_token)
    db.session.commit()

    app_url = current_app.config.get('APP_URL', 'http://127.0.0.1:5050')
    reset_url = f'{app_url.rstrip("/")}/reset-password/{token_value}'
    message_body = (
        f'Hello {user.full_name},\n\n'
        f'You requested a password reset. Use the link below to continue:\n\n{reset_url}\n\n'
        'This link expires in 1 hour.\n'
    )
    html_body = (
        f'<p>Hello {user.full_name},</p>'
        f'<p>You requested a password reset. Use the link below to continue:</p>'
        f'<p><a href="{reset_url}">{reset_url}</a></p>'
        '<p>This link expires in 1 hour.</p>'
    )
    send_email('Password reset request', [user.email], message_body, html_body)
    return reset_token


def complete_password_reset(reset_token: PasswordResetToken, new_password: str):
    if reset_token is None:
        raise ValueError('This password reset link is invalid or expired.')
    if not reset_token.is_valid():
        raise ValueError('This password reset link is invalid or expired.')

    User.validate_password_strength(new_password)

    user = reset_token.user
    user.set_password(new_password)
    reset_token.used_at = datetime.utcnow()
    db.session.commit()
    return user


def update_user_profile(user: User, full_name: str, email: str, profile_photo=None):
    if user is None:
        raise ValueError('User not found.')

    normalized_name = (full_name or '').strip()
    normalized_email = (email or '').strip().lower()
    if not normalized_name or not normalized_email:
        raise ValueError('Full name and email are required.')

    if normalized_email != user.email and User.query.filter_by(email=normalized_email).first():
        raise ValueError('A user with that email already exists.')

    user.full_name = normalized_name
    user.email = normalized_email

    if profile_photo and getattr(profile_photo, 'filename', ''):
        filename = secure_filename(profile_photo.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in {'.png', '.jpg', '.jpeg'}:
            raise ValueError('Profile photo must be a PNG or JPG image.')

        try:
            validate_upload(profile_photo)
        except ValueError:
            raise

        storage = get_storage_service(current_app._get_current_object())
        saved_path = storage.save(profile_photo, f'user_{user.id}_{filename}', folder_name='profiles')
        user.profile_photo_path = saved_path

    db.session.commit()
    return user


def build_user_notifications(user: User):
    if user is None:
        return []

    notifications = []

    overdue_actions = CorrectiveAction.query.filter(
        CorrectiveAction.tenant_id == user.tenant_id,
        CorrectiveAction.due_date < datetime.utcnow(),
        CorrectiveAction.status.notin_(['Completed', 'Verified'])
    ).order_by(CorrectiveAction.due_date.asc()).all()

    if overdue_actions:
        notifications.append({
            'title': 'Overdue corrective action',
            'message': f'{len(overdue_actions)} corrective action(s) are past due and need attention.',
            'category': 'Action required',
            'priority': 'high',
            'link': '/dashboard',
        })

    high_risk_count = sum(
        1 for risk in Risk.query.filter_by(tenant_id=user.tenant_id).all()
        if risk.risk_score is not None and risk.risk_score >= 15
    )
    if high_risk_count:
        notifications.append({
            'title': 'High-risk exposure',
            'message': f'{high_risk_count} high-risk item(s) require review and prioritization.',
            'category': 'Risk',
            'priority': 'high',
            'link': '/risks',
        })

    open_findings = Finding.query.filter(
        Finding.tenant_id == user.tenant_id,
        Finding.status != 'Closed'
    ).count()
    if open_findings:
        notifications.append({
            'title': 'Open findings remain',
            'message': f'{open_findings} finding(s) are still active and should be addressed.',
            'category': 'Finding',
            'priority': 'medium',
            'link': '/findings',
        })

    if not notifications:
        notifications.append({
            'title': 'No active alerts',
            'message': 'There are no overdue actions or priority findings at the moment.',
            'category': 'Status',
            'priority': 'low',
            'link': '/dashboard',
        })

    return notifications
