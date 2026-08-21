import os
import unittest
from io import BytesIO

from app import create_app, db
from app.models import (
    Asset, ApprovalMatrix, ApprovalRecord, AwarenessAssignment, Control, CorrectiveAction,
    Evidence, Finding, Policy, Risk, SecurityAwarenessCampaign, User, UserGroup,
    PasswordResetToken, WorkInstruction,
)
from app.services import complete_password_reset, register_user_account, request_password_reset


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

    def test_service_layer_registers_user_and_resets_password(self):
        user = register_user_account('Service User', 'service-user@example.com', 'StrongPass789!')
        self.assertIsNotNone(user)
        self.assertEqual(user.full_name, 'Service User')
        self.assertTrue(user.check_password('StrongPass789!'))

        reset_token = request_password_reset('service-user@example.com')
        self.assertIsNotNone(reset_token)
        self.assertTrue(reset_token.is_valid())

        complete_password_reset(reset_token, 'NewStrongPass456!')
        db.session.expire_all()
        refreshed = User.query.get(user.id)
        self.assertTrue(refreshed.check_password('NewStrongPass456!'))

    def test_user_can_create_an_account(self):
        token = self.get_csrf_token()
        response = self.client.post('/register', data={
            'full_name': 'New Sign Up User',
            'email': 'signup@example.com',
            'password': 'StrongPass789!',
            'confirm_password': 'StrongPass789!',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        user = User.query.filter_by(email='signup@example.com').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.full_name, 'New Sign Up User')
        self.assertTrue(user.check_password('StrongPass789!'))
        self.assertEqual(user.role.name, 'user')

    def test_user_can_update_profile_and_photo(self):
        user = User(
            tenant_id=1,
            email='profile-user@example.com',
            full_name='Old Name',
            role_id=4,
            is_active=True,
        )
        user.set_password('StrongPass456!')
        db.session.add(user)
        db.session.commit()

        token = self.get_csrf_token()
        login_response = self.client.post('/login', data={
            'email': 'profile-user@example.com',
            'password': 'StrongPass456!',
            'csrf_token': token,
        }, follow_redirects=False)
        self.assertEqual(login_response.status_code, 302)

        token = self.get_csrf_token()
        response = self.client.post('/profile/edit', data={
            'full_name': 'Updated Profile Name',
            'email': 'profile-user@example.com',
            'profile_photo': (BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'), 'avatar.png'),
            'csrf_token': token,
        }, content_type='multipart/form-data', follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        db.session.expire_all()
        updated = User.query.filter_by(email='profile-user@example.com').first()
        self.assertIsNotNone(updated)
        self.assertEqual(updated.full_name, 'Updated Profile Name')
        self.assertTrue(updated.profile_photo_path)

    def test_user_can_request_and_complete_password_reset(self):
        user = User(
            tenant_id=1,
            email='reset-user@example.com',
            full_name='Reset User',
            role_id=4,
            is_active=True,
        )
        user.set_password('OldPassStrong123!')
        db.session.add(user)
        db.session.commit()

        request_response = self.client.post('/forgot-password', data={
            'email': 'reset-user@example.com',
            'csrf_token': self.get_csrf_token(),
        }, follow_redirects=False)
        self.assertEqual(request_response.status_code, 200)

        reset_token = PasswordResetToken.query.filter_by(user_id=user.id).order_by(PasswordResetToken.created_at.desc()).first()
        self.assertIsNotNone(reset_token)

        reset_response = self.client.post(f'/reset-password/{reset_token.token}', data={
            'password': 'NewStrongPass456!',
            'confirm_password': 'NewStrongPass456!',
            'csrf_token': self.get_csrf_token(),
        }, follow_redirects=False)

        self.assertEqual(reset_response.status_code, 302)
        db.session.expire_all()
        refreshed = User.query.get(user.id)
        self.assertTrue(refreshed.check_password('NewStrongPass456!'))
        self.assertFalse(refreshed.check_password('OldPassStrong123!'))

    def test_admin_can_delete_a_user(self):
        self.login_admin()

        user = User(
            tenant_id=1,
            email='delete-me@example.com',
            full_name='Delete Me',
            role_id=4,
            is_active=True,
        )
        user.set_password('StrongPass456!')
        db.session.add(user)
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post(f'/users/{user.id}/delete', data={
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIsNone(User.query.filter_by(id=user.id).first())

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

    def test_evidence_image_preview_route_works(self):
        self.login_admin()

        token = self.get_csrf_token()
        upload_response = self.client.post('/evidence/new', data={
            'title': 'Access Control Screenshot',
            'description': 'Screenshot of access control settings',
            'uploaded_by': 'Operations',
            'file': (BytesIO(b'\x89PNG\r\n\x1a\n' + b'1234567890'), 'access-control.png'),
            'csrf_token': token,
        }, content_type='multipart/form-data', follow_redirects=False)
        self.assertEqual(upload_response.status_code, 302)

        evidence = Evidence.query.filter_by(title='Access Control Screenshot').first()
        self.assertIsNotNone(evidence)
        self.assertTrue(evidence.file_path)
        self.assertTrue(os.path.exists(evidence.file_path))

        detail_response = self.client.get(f'/evidence/{evidence.id}')
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn('/evidence/%d/file' % evidence.id, detail_response.get_data(as_text=True))

        preview_response = self.client.get(f'/evidence/{evidence.id}/file')
        self.assertEqual(preview_response.status_code, 200)
        self.assertEqual(preview_response.mimetype, 'image/png')

    def test_security_awareness_page_includes_training_record_table(self):
        self.login_admin()

        campaign = SecurityAwarenessCampaign(
            tenant_id=1,
            title='Security Awareness - August 2026',
            month_label='August 2026',
            video_title='Monthly security awareness briefing',
            description='Best practices for phishing and secure remote access.',
            video_url='https://example.com/training',
            status='Scheduled',
            created_by_user_id=1,
        )
        db.session.add(campaign)
        db.session.commit()

        assignment = AwarenessAssignment(
            tenant_id=1,
            campaign_id=campaign.id,
            user_id=User.query.filter_by(email='admin@example.com').first().id,
            status='Completed',
            assigned_at=__import__('datetime').datetime.utcnow(),
            watched_at=__import__('datetime').datetime.utcnow(),
            completion_score=100,
            notes='Completed phishing awareness training',
        )
        db.session.add(assignment)
        db.session.commit()

        awareness_response = self.client.get('/security-awareness')
        self.assertEqual(awareness_response.status_code, 200)
        page_html = awareness_response.get_data(as_text=True)
        self.assertIn('Training Record', page_html)
        self.assertIn('Monthly security awareness briefing', page_html)
        self.assertIn('Completed', page_html)

    def test_security_awareness_page_shows_watched_pending_and_in_progress(self):
        self.login_admin()

        campaign = SecurityAwarenessCampaign(
            tenant_id=1,
            title='Security Awareness - September 2026',
            month_label='September 2026',
            video_title='September phishing awareness briefing',
            description='Training on phishing, secure logins, and email hygiene.',
            video_url='https://example.com/september-training',
            status='Scheduled',
            created_by_user_id=1,
        )
        db.session.add(campaign)
        db.session.commit()

        watched_user = User.query.filter_by(email='admin@example.com').first()
        pending_user = User(
            tenant_id=1,
            full_name='Pending User',
            email='pending@example.com',
            password_hash='not-used',
            role_id=User.query.filter_by(email='admin@example.com').first().role_id,
            is_active=True,
        )
        pending_user.set_password('StrongPass123!')
        db.session.add(pending_user)
        db.session.flush()

        in_progress_user = User(
            tenant_id=1,
            full_name='In Progress User',
            email='inprogress@example.com',
            password_hash='not-used',
            role_id=User.query.filter_by(email='admin@example.com').first().role_id,
            is_active=True,
        )
        in_progress_user.set_password('StrongPass123!')
        db.session.add(in_progress_user)
        db.session.flush()

        db.session.add_all([
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=watched_user.id,
                status='Completed',
                assigned_at=__import__('datetime').datetime.utcnow(),
                watched_at=__import__('datetime').datetime.utcnow(),
                completion_score=100,
                notes='Watched the video',
            ),
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=pending_user.id,
                status='Assigned',
                assigned_at=__import__('datetime').datetime.utcnow(),
            ),
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=in_progress_user.id,
                status='In Progress',
                assigned_at=__import__('datetime').datetime.utcnow(),
            ),
        ])
        db.session.commit()

        awareness_response = self.client.get('/security-awareness')
        self.assertEqual(awareness_response.status_code, 200)
        page_html = awareness_response.get_data(as_text=True)
        self.assertIn('Watched', page_html)
        self.assertIn('Pending', page_html)
        self.assertIn('In Progress', page_html)

    def test_security_awareness_page_shows_group_status_breakdown(self):
        self.login_admin()

        campaign = SecurityAwarenessCampaign(
            tenant_id=1,
            title='Security Awareness - October 2026',
            month_label='October 2026',
            video_title='October security briefing',
            description='Training updates for the month.',
            video_url='https://example.com/october-training',
            status='Scheduled',
            created_by_user_id=1,
        )
        db.session.add(campaign)
        db.session.commit()

        admin_user = User.query.filter_by(email='admin@example.com').first()
        watched_user = User(
            tenant_id=1,
            full_name='Watched Group User',
            email='watched-group@example.com',
            password_hash='not-used',
            role_id=admin_user.role_id,
            is_active=True,
        )
        watched_user.set_password('StrongPass123!')
        pending_user = User(
            tenant_id=1,
            full_name='Pending Group User',
            email='pending-group@example.com',
            password_hash='not-used',
            role_id=admin_user.role_id,
            is_active=True,
        )
        pending_user.set_password('StrongPass123!')
        in_progress_user = User(
            tenant_id=1,
            full_name='In Progress Group User',
            email='inprogress-group@example.com',
            password_hash='not-used',
            role_id=admin_user.role_id,
            is_active=True,
        )
        in_progress_user.set_password('StrongPass123!')
        db.session.add_all([watched_user, pending_user, in_progress_user])
        db.session.flush()

        group = UserGroup(tenant_id=1, name='Security Operations', description='Security team training group')
        db.session.add(group)
        db.session.flush()
        group.users.extend([admin_user, watched_user, pending_user, in_progress_user])

        db.session.add_all([
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=admin_user.id,
                status='Completed',
                assigned_at=__import__('datetime').datetime.utcnow(),
                watched_at=__import__('datetime').datetime.utcnow(),
                completion_score=100,
                notes='Watched',
            ),
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=watched_user.id,
                status='Completed',
                assigned_at=__import__('datetime').datetime.utcnow(),
                watched_at=__import__('datetime').datetime.utcnow(),
                completion_score=100,
                notes='Watched',
            ),
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=pending_user.id,
                status='Assigned',
                assigned_at=__import__('datetime').datetime.utcnow(),
            ),
            AwarenessAssignment(
                tenant_id=1,
                campaign_id=campaign.id,
                user_id=in_progress_user.id,
                status='In Progress',
                assigned_at=__import__('datetime').datetime.utcnow(),
            ),
        ])
        db.session.commit()

        awareness_response = self.client.get('/security-awareness')
        self.assertEqual(awareness_response.status_code, 200)
        page_html = awareness_response.get_data(as_text=True)
        self.assertIn('User Group Status', page_html)
        self.assertIn('Security Operations', page_html)
        self.assertIn('Watched', page_html)
        self.assertIn('Pending', page_html)
        self.assertIn('In Progress', page_html)

    def test_security_awareness_video_uses_browser_completion_tracking(self):
        self.login_admin()

        campaign = SecurityAwarenessCampaign(
            tenant_id=1,
            title='Security Awareness - November 2026',
            month_label='November 2026',
            video_title='November security briefing',
            description='Video training for the month.',
            video_url='https://example.com/video.mp4',
            status='Scheduled',
            created_by_user_id=1,
        )
        db.session.add(campaign)
        db.session.commit()

        assignment = AwarenessAssignment(
            tenant_id=1,
            campaign_id=campaign.id,
            user_id=User.query.filter_by(email='admin@example.com').first().id,
            status='Assigned',
            assigned_at=__import__('datetime').datetime.utcnow(),
        )
        db.session.add(assignment)
        db.session.commit()

        awareness_response = self.client.get('/security-awareness')
        page_html = awareness_response.get_data(as_text=True)
        self.assertIn('<video', page_html)
        self.assertIn('data-assignment-id', page_html)
        self.assertIn('markWatched', page_html)

    def test_admin_can_upload_video_for_security_awareness_campaign(self):
        self.login_admin()

        token = self.get_csrf_token()
        response = self.client.post('/security-awareness/generate', data={
            'title': 'Security Awareness - September 2026',
            'month_label': 'September 2026',
            'video_title': 'September security briefing',
            'description': 'Video training for the month.',
            'video_url': '',
            'video_file': (BytesIO(b'\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00'), 'security-briefing.mp4'),
            'csrf_token': token,
        }, content_type='multipart/form-data', follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        campaign = SecurityAwarenessCampaign.query.filter_by(title='Security Awareness - September 2026').first()
        self.assertIsNotNone(campaign)
        self.assertTrue(campaign.video_url)
        self.assertIn('/security-awareness/video/', campaign.video_url)

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

    def test_notifications_page_renders_alerts(self):
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

        CorrectiveAction(
            tenant_id=1,
            finding_id=finding_record.id,
            description='Schedule phishing awareness training for all staff',
            owner='IT Security',
            due_date=__import__('datetime').datetime.utcnow().replace(year=2020),
            status='In Progress',
            created_by_user_id=1,
        )

        response = self.client.get('/notifications')
        self.assertEqual(response.status_code, 200)
        content = response.get_data(as_text=True)
        self.assertIn('Notifications', content)
        self.assertIn('Open findings remain', content)

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
