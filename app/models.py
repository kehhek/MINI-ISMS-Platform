from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from datetime import datetime


class Tenant(db.Model):
    __tablename__ = 'tenants'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(50), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship('User', backref='tenant', lazy=True)
    assets = db.relationship('Asset', backref='tenant', lazy=True)
    risks = db.relationship('Risk', backref='tenant', lazy=True)
    policies = db.relationship('Policy', backref='tenant', lazy=True)
    controls = db.relationship('Control', backref='tenant', lazy=True)
    findings = db.relationship('Finding', backref='tenant', lazy=True)
    evidence = db.relationship('Evidence', backref='tenant', lazy=True)
    audit_events = db.relationship('AuditEvent', backref='tenant', lazy=True)

    def __repr__(self):
        return f'<Tenant {self.name}>'


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Role {self.name}>'


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    role = db.relationship('Role', backref='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    name = db.Column(db.String(150), nullable=False)
    asset_type = db.Column(db.String(50))
    owner = db.Column(db.String(100))
    classification = db.Column(db.String(50))
    location = db.Column(db.String(150))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    risks = db.relationship('Risk', backref='asset', lazy=True)

    def __repr__(self):
        return f'<Asset {self.name}>'


class Risk(db.Model):
    __tablename__ = 'risks'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=True)
    likelihood = db.Column(db.Integer)
    impact = db.Column(db.Integer)
    status = db.Column(db.String(50), default='Open')
    owner = db.Column(db.String(100))
    identified_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    @property
    def risk_score(self):
        if self.likelihood and self.impact:
            return self.likelihood * self.impact
        return None

    def __repr__(self):
        return f'<Risk {self.title}>'


class Policy(db.Model):
    __tablename__ = 'policies'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    title = db.Column(db.String(200), nullable=False)
    version = db.Column(db.String(20), default='1.0')
    owner = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Draft')
    approved_date = db.Column(db.DateTime, nullable=True)
    review_date = db.Column(db.DateTime, nullable=True)
    content_summary = db.Column(db.Text)
    document_filename = db.Column(db.String(255), nullable=True)
    document_path = db.Column(db.String(500), nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def __repr__(self):
        return f'<Policy {self.title}>'


class Control(db.Model):
    __tablename__ = 'controls'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    control_id = db.Column(db.String(20))
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    control_type = db.Column(db.String(50))
    implementation_status = db.Column(db.String(50), default='Not Implemented')
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'), nullable=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    risk = db.relationship('Risk', backref='controls')
    policy = db.relationship('Policy', backref='controls')

    def __repr__(self):
        return f'<Control {self.name}>'


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='Medium')
    status = db.Column(db.String(50), default='Open')
    control_id = db.Column(db.Integer, db.ForeignKey('controls.id'), nullable=True)
    audit_name = db.Column(db.String(150))
    identified_date = db.Column(db.DateTime, default=datetime.utcnow)
    identified_by = db.Column(db.String(100))
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    control = db.relationship('Control', backref='findings')

    def __repr__(self):
        return f'<Finding {self.title}>'


class CorrectiveAction(db.Model):
    __tablename__ = 'corrective_actions'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    owner = db.Column(db.String(100))
    due_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='Not Started')
    completed_date = db.Column(db.DateTime, nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    finding = db.relationship('Finding', backref='corrective_actions')

    def __repr__(self):
        return f'<CorrectiveAction {self.id}>'


class Evidence(db.Model):
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(255))
    file_path = db.Column(db.String(500))
    description = db.Column(db.Text)
    uploaded_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(100))
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    file_hash = db.Column(db.String(128))
    file_size = db.Column(db.Integer, default=0)
    mime_type = db.Column(db.String(100))
    retention_policy = db.Column(db.String(50), default='90 days')
    archived_at = db.Column(db.DateTime, nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    storage_provider = db.Column(db.String(50), default='local')

    control_id = db.Column(db.Integer, db.ForeignKey('controls.id'), nullable=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)

    control = db.relationship('Control', backref='evidence_items')
    finding = db.relationship('Finding', backref='evidence_items')

    def __repr__(self):
        return f'<Evidence {self.title}>'


class AuditEvent(db.Model):
    __tablename__ = 'audit_events'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    entity_type = db.Column(db.String(100), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    before_value = db.Column(db.Text, nullable=True)
    after_value = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='audit_events')

    def __repr__(self):
        return f'<AuditEvent {self.entity_type}:{self.entity_id}>'