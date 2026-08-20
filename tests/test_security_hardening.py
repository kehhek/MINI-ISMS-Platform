import os
import unittest

import pyotp

from app import create_app, db
from app.models import User
from app.routes import FAILED_LOGIN_ATTEMPTS


class SecurityHardeningTest(unittest.TestCase):
    def setUp(self):
        FAILED_LOGIN_ATTEMPTS.clear()
        os.environ['SECRET_KEY'] = 'test-secret'
        os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
        os.environ['ADMIN_EMAIL'] = 'admin@example.com'
        os.environ['ADMIN_PASSWORD'] = 'StrongPass123!'
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

    def tearDown(self):
        FAILED_LOGIN_ATTEMPTS.clear()
        self.app_context.pop()

    def get_csrf_token(self):
        with self.client.session_transaction() as session:
            token = session.get('_csrf_token')
            if not token:
                token = 'test-csrf-token'
                session['_csrf_token'] = token
            return token

    def test_state_changing_posts_require_csrf_token(self):
        token = self.get_csrf_token()
        self.client.post('/login', data={
            'email': 'admin@example.com',
            'password': 'StrongPass123!',
            'csrf_token': token,
        }, follow_redirects=False)

        no_token_response = self.client.post('/assets/new', data={
            'name': 'Test Asset',
            'asset_type': 'Hardware',
            'owner': 'Ops',
            'classification': 'Internal',
            'description': 'Needs inspection',
        }, follow_redirects=False)
        self.assertEqual(no_token_response.status_code, 400)

    def test_login_is_rate_limited_after_repeated_failures(self):
        for _ in range(6):
            token = self.get_csrf_token()
            response = self.client.post('/login', data={
                'email': 'admin@example.com',
                'password': 'wrong-password',
                'csrf_token': token,
            }, follow_redirects=False)

        self.assertEqual(response.status_code, 429)

    def test_security_headers_are_added_to_responses(self):
        response = self.client.get('/login')
        self.assertIn('X-Frame-Options', response.headers)
        self.assertIn('X-Content-Type-Options', response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')

    def test_login_requires_mfa_when_enabled(self):
        user = User.query.filter_by(email='admin@example.com').first()
        user.mfa_enabled = True
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()

        token = self.get_csrf_token()
        response = self.client.post('/login', data={
            'email': 'admin@example.com',
            'password': 'StrongPass123!',
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/mfa/verify')

        verify_response = self.client.post('/mfa/verify', data={
            'code': pyotp.TOTP(user.mfa_secret).now(),
            'csrf_token': token,
        }, follow_redirects=False)

        self.assertEqual(verify_response.status_code, 302)


if __name__ == '__main__':
    unittest.main()
