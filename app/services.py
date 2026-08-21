from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from flask import current_app
from werkzeug.utils import secure_filename

from app import db
from app.models import PasswordResetToken, Role, Tenant, User
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
