import os
import unittest
from io import BytesIO

from app import create_app, db
from app.models import Asset, Control, Evidence, Policy, Risk, User


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
