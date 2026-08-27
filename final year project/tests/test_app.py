import os
import tempfile
import unittest

from app import create_app
from app.database import get_db, init_db


class PhishGuardTestCase(unittest.TestCase):
    def setUp(self):
        self.database_fd, database_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": database_path,
                "SECRET_KEY": "test-secret",
            }
        )
        with self.app.app_context():
            init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.database_fd)
        os.unlink(self.app.config["DATABASE"])

    def test_home_and_safe_scan(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.post("/scan", data={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"estimated phishing probability", response.data)

    def test_account_scan_history_and_admin_access(self):
        response = self.client.post(
            "/auth/register",
            data={"name": "Test User", "email": "test@example.com", "password": "password123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.client.post("/scan", data={"url": "http://192.168.0.1/%61?x=1&y=2"})
        self.assertIn(b"192.168.0.1", self.client.get("/dashboard").data)

        with self.app.app_context():
            get_db().execute("UPDATE users SET is_admin = 1 WHERE email = ?", ("test@example.com",))
            get_db().commit()
        self.assertEqual(self.client.get("/admin").status_code, 200)

        response = self.client.post("/auth/delete-account", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            self.assertIsNone(get_db().execute("SELECT id FROM users WHERE email = ?", ("test@example.com",)).fetchone())


if __name__ == "__main__":
    unittest.main()
