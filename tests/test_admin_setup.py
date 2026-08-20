import os
import unittest
from io import BytesIO

from app import create_app, db
from app.models import Asset, ApprovalMatrix, ApprovalRecord, Control, CorrectiveAction, Evidence, Finding, Policy, Risk, User, UserGroup, WorkInstruction


class AdminSetupFlowTest(unittest.TestCase):
    def setUp(self):
        os.environ['SECRET_KEY'] = 'test-secret'
        os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
        os.environ['ADMIN_EMAIL'] = 'admin@example.com'
        os.environ['ADMIN_PASSWORD'] = 'StrongPass123!'
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        self.app_context.pop()

    def get_csrf_token(self):
        self.client.get('/login')
        with self.client.session_transaction() as session:
            return session.get('_csrf_token')

    def login_admin(self):
        token = self.get_csrf_token()
        return self.client.post('/login', data={
            'email': 'admin@example.com',
            'password': 'StrongPass123!',
            'csrf_token': token,
        }, follow_redirects=False)

    def test_default_admin_is_created_from_environment(self):
        user = User.query.filter_by(email='admin@example.com').first()
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password('StrongPass123!'))
        self.assertEqual(user.role.name, 'admin')

    def test_default_admin_is_not_created_without_environment_credentials(self):
        os.environ.pop('ADMIN_EMAIL', None)
        os.environ.pop('ADMIN_PASSWORD', None)

        app = create_app()
        with app.app_context():
            user = User.query.filter_by(email='admin@example.com').first()
            self.assertIsNone(user)

    def test_admin_can_edit_existing_asset(self):
        self.login_admin()
        asset = Asset(tenant_id=1, name='Old Server', asset_type='Hardware', owner='Ops', classification='Internal', description='Old')
        db.session.add(asset)
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post(f'/assets/{asset.id}/edit', data={
            'name': 'Updated Server',
            'asset_type': 'Hardware',
            'owner': 'Security Team',
            'classification': 'Confidential',
            'location': 'DC-2',
            'description': 'Updated description',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        db.session.expire_all()
        updated = Asset.query.get(asset.id)
        self.assertEqual(updated.name, 'Updated Server')
        self.assertEqual(updated.owner, 'Security Team')

    def test_admin_can_edit_existing_policy(self):
        self.login_admin()
        policy = Policy(tenant_id=1, title='Old Policy', version='1.0', owner='Ops', status='Draft', content_summary='Old summary')
        db.session.add(policy)
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post(f'/policies/{policy.id}/edit', data={
            'title': 'Updated Policy',
            'version': '2.0',
            'owner': 'Compliance',
            'status': 'Approved',
            'review_date': '2026-12-31',
            'content_summary': 'Updated summary',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        db.session.expire_all()
        updated = Policy.query.get(policy.id)
        self.assertEqual(updated.title, 'Updated Policy')
        self.assertEqual(updated.version, '2.0')
        self.assertEqual(updated.owner, 'Compliance')

    def test_admin_can_upload_pdf_policy_document(self):
        self.login_admin()

        token = self.get_csrf_token()
        response = self.client.post('/policies/new', data={
            'title': 'Remote Access Policy',
            'version': '3.0',
            'owner': 'IT Security',
            'status': 'Approved',
            'review_date': '2026-12-31',
            'content_summary': 'Remote access controls',
            'file': (BytesIO(b'%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF'), 'policy.pdf'),
            'csrf_token': token,
        }, content_type='multipart/form-data', follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        policy = Policy.query.filter_by(title='Remote Access Policy').first()
        self.assertIsNotNone(policy)
        self.assertEqual(policy.document_filename, 'policy.pdf')
        self.assertTrue(policy.document_path)

    def test_admin_can_create_work_instruction(self):
        self.login_admin()

        token = self.get_csrf_token()
        response = self.client.post('/work-instructions/new', data={
            'title': 'Password Reset Procedure',
            'owner': 'IT Support',
            'status': 'Approved',
            'review_date': '2026-12-31',
            'steps': '1. Verify identity\n2. Reset credential\n3. Notify user',
            'document_filename': 'password-reset.pdf',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        instruction = WorkInstruction.query.filter_by(title='Password Reset Procedure').first()
        self.assertIsNotNone(instruction)
        self.assertEqual(instruction.owner, 'IT Support')
        self.assertIn('Reset credential', instruction.steps)

    def test_admin_can_create_a_new_user(self):
        self.login_admin()

        token = self.get_csrf_token()
        response = self.client.post('/users/new', data={
            'full_name': 'Jane Analyst',
            'email': 'jane@example.com',
            'password': 'StrongPass456!',
            'role_id': '4',
            'is_active': '1',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        user = User.query.filter_by(email='jane@example.com').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.full_name, 'Jane Analyst')
        self.assertTrue(user.check_password('StrongPass456!'))
        self.assertEqual(user.role.name, 'user')

    def test_admin_can_create_a_user_group(self):
        self.login_admin()

        token = self.get_csrf_token()
        response = self.client.post('/user-groups/new', data={
            'name': 'Operations Team',
            'description': 'Core operational support team',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        group = UserGroup.query.filter_by(name='Operations Team').first()
        self.assertIsNotNone(group)
        self.assertEqual(group.tenant_id, 1)

    def test_standard_user_can_view_evidence(self):
        self.login_admin()
        user = User(
            tenant_id=1,
            email='standard@example.com',
            full_name='Standard User',
            role_id=4,
            is_active=True,
        )
        user.set_password('StrongPass456!')
        db.session.add(user)
        db.session.commit()

        evidence = Evidence(
            tenant_id=1,
            title='Quarterly Control Evidence',
            filename='quarterly.pdf',
            file_path='/tmp/quarterly.pdf',
            description='Quarterly control validation evidence',
            uploaded_by='Standard User',
            uploaded_by_user_id=user.id,
            storage_provider='local',
            file_size=100,
            file_hash='abc',
            mime_type='application/pdf',
        )
        db.session.add(evidence)
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post('/login', data={
            'email': 'standard@example.com',
            'password': 'StrongPass456!',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        list_response = self.client.get('/evidence')
        self.assertEqual(list_response.status_code, 200)

        detail_response = self.client.get(f'/evidence/{evidence.id}')
        self.assertEqual(detail_response.status_code, 200)

    def test_dashboard_lists_overdue_actions(self):
        self.login_admin()

        finding_record = Finding(
            tenant_id=1,
            title='Training gap',
            description='Awareness training needs to be completed',
            severity='High',
            status='Open',
            created_by_user_id=1,
        )
        db.session.add(finding_record)
        db.session.commit()

        action = CorrectiveAction(
            tenant_id=1,
            finding_id=finding_record.id,
            description='Schedule phishing awareness training for all staff',
            owner='IT Security',
            due_date=__import__('datetime').datetime.utcnow().replace(year=2020),
            status='In Progress',
            created_by_user_id=1,
        )
        db.session.add(action)
        db.session.commit()

        dashboard_response = self.client.get('/dashboard')
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIn('Schedule phishing awareness training for all staff', dashboard_response.get_data(as_text=True))

    def test_authenticated_user_can_view_own_profile(self):
        self.login_admin()

        profile_response = self.client.get('/profile')
        self.assertEqual(profile_response.status_code, 200)
        self.assertIn('System Administrator', profile_response.get_data(as_text=True))

        user_detail_response = self.client.get(f'/users/{User.query.filter_by(email="admin@example.com").first().id}')
        self.assertEqual(user_detail_response.status_code, 200)

    def test_risk_crud_routes_work(self):
        self.login_admin()

        token = self.get_csrf_token()
        create_response = self.client.post('/risks/new', data={
            'title': 'Phishing Risk',
            'description': 'Users may click malicious links.',
            'asset_id': '',
            'likelihood': '3',
            'impact': '4',
            'owner': 'IT Security',
            'status': 'Open',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(create_response.status_code, 302)

        risk = Risk.query.filter_by(title='Phishing Risk').first()
        self.assertIsNotNone(risk)

        view_response = self.client.get(f'/risks/{risk.id}')
        self.assertEqual(view_response.status_code, 200)

        token = self.get_csrf_token()
        edit_response = self.client.post(f'/risks/{risk.id}/edit', data={
            'title': 'Updated Phishing Risk',
            'description': 'Updated description for phishing awareness training.',
            'asset_id': '',
            'likelihood': '5',
            'impact': '5',
            'owner': 'Security Team',
            'status': 'Mitigated',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(edit_response.status_code, 302)
        db.session.expire_all()
        self.assertEqual(Risk.query.get(risk.id).title, 'Updated Phishing Risk')

        token = self.get_csrf_token()
        delete_response = self.client.post(f'/risks/{risk.id}/delete', data={'csrf_token': token}, follow_redirects=False)
        self.assertEqual(delete_response.status_code, 302)
        self.assertIsNone(Risk.query.get(risk.id))

    def test_critical_record_can_be_approved_and_locked(self):
        self.login_admin()

        risk = Risk(tenant_id=1, title='Critical access control risk', description='MFA issue', likelihood=5, impact=5, owner='Security Team', status='Open')
        db.session.add(risk)
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post(f'/risks/{risk.id}/approve', data={
            'decision': 'approve',
            'reason': 'Risk accepted after control remediation',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        db.session.expire_all()
        self.assertEqual(Risk.query.get(risk.id).approval_status, 'Approved')
        self.assertIsNotNone(Risk.query.get(risk.id).locked_at)
        self.assertEqual(ApprovalRecord.query.filter_by(entity_type='risk', entity_id=risk.id).count(), 1)

    def test_audit_export_includes_signed_history_and_hashes(self):
        self.login_admin()

        risk = Risk(tenant_id=1, title='Signed export risk', description='Needs approval', likelihood=4, impact=5, owner='Security Team', status='Open')
        db.session.add(risk)
        db.session.commit()

        approval = ApprovalRecord(
            tenant_id=1,
            entity_type='risk',
            entity_id=risk.id,
            action='approved',
            approver_id=1,
            reason='Reviewed by security team',
            signature_hash='test-signature-hash',
        )
        db.session.add(approval)
        db.session.commit()

        response = self.client.get('/reports/audit-log.csv')
        self.assertEqual(response.status_code, 200)
        content = response.get_data(as_text=True)
        self.assertIn('signature_hash', content)
        self.assertIn('signed_change', content)
        self.assertIn('test-signature-hash', content)

    def test_approval_matrix_is_seeded_for_role_based_signoff(self):
        self.login_admin()
        matrix = ApprovalMatrix.query.filter_by(entity_type='risk').first()
        self.assertIsNotNone(matrix)
        self.assertIn(matrix.required_role, ['admin', 'security_manager'])

    def test_asset_control_and_evidence_crud_routes_work(self):
        self.login_admin()

        asset = Asset(tenant_id=1, name='Database Server', asset_type='Hardware', owner='Ops', classification='Confidential', description='Primary DB')
        db.session.add(asset)
        db.session.commit()

        asset_view = self.client.get(f'/assets/{asset.id}')
        self.assertEqual(asset_view.status_code, 200)

        token = self.get_csrf_token()
        asset_edit = self.client.post(f'/assets/{asset.id}/edit', data={
            'name': 'Updated Database Server',
            'asset_type': 'Hardware',
            'owner': 'Platform Team',
            'classification': 'Restricted',
            'location': 'Rack A',
            'description': 'Updated description',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(asset_edit.status_code, 302)
        self.assertEqual(Asset.query.get(asset.id).name, 'Updated Database Server')

        risk = Risk(tenant_id=1, title='Data Loss Risk', description='Potential outage', likelihood=4, impact=5, owner='Ops', status='Open')
        db.session.add(risk)
        db.session.commit()

        control = Control(
            tenant_id=1,
            control_id='A.8.2',
            name='Database Backup Control',
            description='Daily backup',
            control_type='Preventive',
            implementation_status='Implemented',
            risk_id=risk.id,
            created_by_user_id=1,
        )
        db.session.add(control)
        db.session.commit()

        control_view = self.client.get(f'/controls/{control.id}')
        self.assertEqual(control_view.status_code, 200)

        token = self.get_csrf_token()
        control_edit = self.client.post(f'/controls/{control.id}/edit', data={
            'control_id': 'A.8.3',
            'name': 'Updated Backup Control',
            'description': 'Daily offsite backup',
            'control_type': 'Corrective',
            'implementation_status': 'Partially Implemented',
            'risk_id': risk.id,
            'policy_id': '',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(control_edit.status_code, 302)
        self.assertEqual(Control.query.get(control.id).name, 'Updated Backup Control')

        evidence = Evidence(
            tenant_id=1,
            title='Backup Report',
            filename='report.pdf',
            file_path='/tmp/report.pdf',
            description='Daily backup report',
            uploaded_by='Ops',
            uploaded_by_user_id=1,
            control_id=control.id,
            storage_provider='local',
            file_size=100,
            file_hash='abc',
            mime_type='application/pdf'
        )
        db.session.add(evidence)
        db.session.commit()

        evidence_view = self.client.get(f'/evidence/{evidence.id}')
        self.assertEqual(evidence_view.status_code, 200)

        token = self.get_csrf_token()
        evidence_edit = self.client.post(f'/evidence/{evidence.id}/edit', data={
            'title': 'Updated Backup Report',
            'uploaded_by': 'Security Team',
            'description': 'Updated backup verification report',
            'control_id': control.id,
            'finding_id': '',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(evidence_edit.status_code, 302)
        self.assertEqual(Evidence.query.get(evidence.id).title, 'Updated Backup Report')

        token = self.get_csrf_token()
        asset_delete = self.client.post(f'/assets/{asset.id}/delete', data={'csrf_token': token}, follow_redirects=False)
        self.assertEqual(asset_delete.status_code, 302)
        self.assertIsNone(Asset.query.get(asset.id))

        token = self.get_csrf_token()
        control_delete = self.client.post(f'/controls/{control.id}/delete', data={'csrf_token': token}, follow_redirects=False)
        self.assertEqual(control_delete.status_code, 302)
        self.assertIsNone(Control.query.get(control.id))

        token = self.get_csrf_token()
        evidence_delete = self.client.post(f'/evidence/{evidence.id}/delete', data={'csrf_token': token}, follow_redirects=False)
        self.assertEqual(evidence_delete.status_code, 302)
        self.assertIsNone(Evidence.query.get(evidence.id))


if __name__ == '__main__':
    unittest.main()
