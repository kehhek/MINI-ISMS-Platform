import os
import unittest

from app import create_app
from app.models import User


class AdminSetupFlowTest(unittest.TestCase):
    def setUp(self):
        os.environ['SECRET_KEY'] = 'test-secret'
        os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
        os.environ['ADMIN_EMAIL'] = 'admin@example.com'
        os.environ['ADMIN_PASSWORD'] = 'StrongPass123!'
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_default_admin_is_created_from_environment(self):
        user = User.query.filter_by(email='admin@example.com').first()
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password('StrongPass123!'))
        self.assertEqual(user.role.name, 'admin')


if __name__ == '__main__':
    unittest.main()
