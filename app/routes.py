from functools import wraps
from io import StringIO
import csv
import os
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename

from app import db
from app.storage import get_storage_service
from app.models import (
    Tenant, Asset, Risk, Policy, Control, Finding, CorrectiveAction, Evidence, User, AuditEvent, Role
)

main = Blueprint('main', __name__)


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


def log_audit_event(user, entity_type, entity_id, action, before_value=None, after_value=None):
    if user is None:
        return
    event = AuditEvent(
        tenant_id=user.tenant_id,
        user_id=user.id,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        before_value=str(before_value) if before_value is not None else None,
        after_value=str(after_value) if after_value is not None else None,
        ip_address=request.remote_addr if request else None,
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
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            log_audit_event(user, 'user', user.id, 'login')
            flash('Welcome back.')
            return redirect(url_for('main.dashboard'))

        flash('Invalid email or password.')

    return render_template('login.html')


@main.route('/logout')
@login_required
def logout():
    log_audit_event(current_user, 'user', current_user.id, 'logout')
    logout_user()
    return redirect(url_for('main.dashboard'))


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
            created_by_user_id=current_user.id,
        )
        db.session.add(risk)
        db.session.commit()
        log_audit_event(current_user, 'risk', risk.id, 'created', before_value=None, after_value=risk.title)
        flash('Risk added successfully.')
        return redirect(url_for('main.risks_list'))
    assets = Asset.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('risk_form.html', assets=assets)


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
        db.session.add(policy)
        db.session.commit()
        log_audit_event(current_user, 'policy', policy.id, 'created', before_value=None, after_value=policy.title)
        flash('Policy added successfully.')
        return redirect(url_for('main.policies_list'))
    return render_template('policy_form.html')


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
def evidence_list():
    evidence = Evidence.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('evidence_list.html', evidence=evidence)


@main.route('/evidence/new', methods=['GET', 'POST'])
@login_required
@require_roles('admin', 'security_manager', 'user')
def evidence_new():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
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
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(['id', 'entity_type', 'entity_id', 'action', 'user_id', 'created_at'])
    for item in events:
        writer.writerow([item.id, item.entity_type, item.entity_id, item.action, item.user_id, item.created_at])

    output = csv_buffer.getvalue().encode('utf-8')
    log_audit_event(current_user, 'report', None, 'exported_audit_log_csv')
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

    overdue_actions_count = CorrectiveAction.query.filter(
        CorrectiveAction.tenant_id == current_user.tenant_id,
        CorrectiveAction.due_date < datetime.utcnow(),
        CorrectiveAction.status.notin_(['Completed', 'Verified'])
    ).count()

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
        overdue_actions_count=overdue_actions_count,
        high_risk_count=high_risk_count,
        severity_counts=severity_counts,
        control_status_counts=control_status_counts,
        risk_buckets=risk_buckets
    )