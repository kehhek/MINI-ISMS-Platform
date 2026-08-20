from flask import Flask, session, request
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import text
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()


def add_missing_columns_for_legacy_db():
    from sqlalchemy import inspect

    inspector = inspect(db.engine)
    table_columns = {
        'tenants': [],
        'roles': ['tenant_id'],
        'users': ['tenant_id', 'role_id', 'is_active', 'mfa_enabled', 'mfa_secret', 'last_login_at'],
        'assets': ['tenant_id', 'created_by_user_id'],
        'risks': ['tenant_id', 'created_by_user_id'],
        'policies': ['tenant_id', 'created_by_user_id', 'document_filename', 'document_path', 'mime_type', 'file_size'],
        'controls': ['tenant_id', 'created_by_user_id'],
        'findings': ['tenant_id', 'created_by_user_id'],
        'corrective_actions': ['tenant_id', 'created_by_user_id'],
        'evidence': [
            'tenant_id', 'uploaded_by_user_id', 'file_hash', 'file_size', 'mime_type',
            'retention_policy', 'archived_at', 'deleted_at', 'storage_provider', 'control_id', 'finding_id'
        ],
        'audit_events': ['tenant_id', 'user_id'],
    }

    for table_name, expected_columns in table_columns.items():
        if table_name not in inspector.get_table_names():
            continue

        existing_columns = {column['name'] for column in inspector.get_columns(table_name)}
        for column_name in expected_columns:
            if column_name in existing_columns:
                continue

            if column_name in {'tenant_id', 'role_id', 'user_id', 'created_by_user_id', 'uploaded_by_user_id', 'control_id', 'finding_id'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} INTEGER DEFAULT 1'))
            elif column_name in {'file_size'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} INTEGER DEFAULT 0'))
            elif column_name in {'is_active', 'mfa_enabled'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} BOOLEAN DEFAULT 0'))
            elif column_name in {'last_login_at', 'archived_at', 'deleted_at'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} DATETIME'))
            elif column_name in {'mfa_secret'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} VARCHAR(64)'))
            elif column_name in {'document_filename', 'document_path', 'mime_type'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} TEXT'))
            elif column_name in {'file_size'}:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} INTEGER DEFAULT 0'))
            else:
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} TEXT'))
    db.session.commit()


def seed_default_data():
    from app.models import Tenant, Role, User

    tenant = Tenant.query.first()
    if not tenant:
        tenant_name = os.getenv('TENANT_NAME', 'Default Tenant')
        tenant_slug = os.getenv('TENANT_SLUG', 'default-tenant')
        tenant = Tenant(name=tenant_name, slug=tenant_slug, status='active')
        db.session.add(tenant)
        db.session.commit()

    for role_name, description in [
        ('admin', 'System administrator'),
        ('security_manager', 'Security manager'),
        ('auditor', 'Auditor'),
        ('user', 'Standard user'),
    ]:
        if not Role.query.filter_by(tenant_id=tenant.id, name=role_name).first():
            db.session.add(Role(tenant_id=tenant.id, name=role_name, description=description))
    db.session.commit()

    default_admin_email = os.getenv('ADMIN_EMAIL')
    default_admin_password = os.getenv('ADMIN_PASSWORD')
    default_admin_name = os.getenv('ADMIN_NAME', 'System Administrator')

    if not default_admin_email or not default_admin_password:
        return tenant

    existing_admin = User.query.filter_by(email=default_admin_email).first()
    if not existing_admin:
        admin_role = Role.query.filter_by(tenant_id=tenant.id, name='admin').first()
        if admin_role is None:
            admin_role = Role(tenant_id=tenant.id, name='admin', description='System administrator')
            db.session.add(admin_role)
            db.session.commit()

        admin_user = User(
            tenant_id=tenant.id,
            email=default_admin_email,
            full_name=default_admin_name,
            role_id=admin_role.id,
            is_active=True,
        )
        admin_user.set_password(default_admin_password)
        db.session.add(admin_user)
        db.session.commit()

    return tenant


def create_app():
    from app import models  # import before create_all so tables are registered

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///mini_isms.db')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        raise RuntimeError('SECRET_KEY environment variable is required. Set it before starting the app.')
    app.config['ENV'] = 'production' if os.getenv('APP_ENV') == 'production' else 'development'
    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    app.config['ALLOWED_UPLOAD_EXTENSIONS'] = {'.pdf', '.png', '.jpg', '.jpeg', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt'}
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', '1' if os.getenv('APP_ENV') == 'production' else '0') == '1'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['STORAGE_BACKEND'] = os.getenv('STORAGE_BACKEND', 'local')
    app.config['STORAGE_BUCKET'] = os.getenv('STORAGE_BUCKET', 'mini-isms-local')
    app.config['S3_ENDPOINT_URL'] = os.getenv('S3_ENDPOINT_URL')
    app.config['S3_REGION'] = os.getenv('S3_REGION', 'us-east-1')
    app.config['S3_ACCESS_KEY_ID'] = os.getenv('S3_ACCESS_KEY_ID')
    app.config['S3_SECRET_ACCESS_KEY'] = os.getenv('S3_SECRET_ACCESS_KEY')

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    @app.before_request
    def ensure_csrf_token():
        if '_csrf_token' not in session:
            import secrets
            session['_csrf_token'] = secrets.token_urlsafe(32)

    @app.before_request
    def enforce_csrf_on_state_changes():
        if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return None
        if request.path.startswith('/static'):
            return None
        submitted = request.form.get('csrf_token')
        if submitted != session.get('_csrf_token'):
            from flask import abort
            abort(400, description='Invalid or missing CSRF token.')

    @app.after_request
    def add_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        add_missing_columns_for_legacy_db()
        seed_default_data()

    from app.routes import main
    app.register_blueprint(main)

    return app