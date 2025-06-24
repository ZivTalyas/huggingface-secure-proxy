import unittest
import os
import sys
import json
import base64
from fastapi.testclient import TestClient

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.frontend.main import app as frontend_app
from app.backend.main import app as backend_app

class TestSecureInputProxy(unittest.TestCase):    
    def setUp(self):
        # Create test clients for both frontend and backend
        self.frontend_client = TestClient(frontend_app)
        self.backend_client = TestClient(backend_app)
        
        # Test data
        self.safe_text = "Hello, this is a safe message."
        self.unsafe_text = "You're so dumb it's funny."
        self.test_file_content = b"This is a test file content."
        self.test_file_b64 = base64.b64encode(self.test_file_content).decode('utf-8')
    
    def test_frontend_health(self):
        """Test frontend health check endpoint"""
        response = self.frontend_client.get("/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.json())
    
    def test_backend_health(self):
        """Test backend health check endpoint"""
        response = self.backend_client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
    
    def test_validate_safe_text(self):
        """Test validation of safe text input"""
        response = self.frontend_client.post(
            "/validate-input",
            json={"text": self.safe_text, "security_level": "high"}
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "safe")
    
    def test_validate_unsafe_text(self):
        """Test validation of unsafe text input"""
        response = self.frontend_client.post(
            "/validate-input",
            json={"text": self.unsafe_text, "security_level": "high"}
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "unsafe")
    
    def test_validate_file(self):
        """Test file validation"""
        response = self.frontend_client.post(
            "/validate-input",
            json={"file": self.test_file_b64, "security_level": "high"}
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)
    
    def test_invalid_security_level(self):
        """Test validation with invalid security level"""
        response = self.frontend_client.post(
            "/validate-input",
            json={"text": self.safe_text, "security_level": "invalid"}
        )
        self.assertEqual(response.status_code, 400)
    
    def test_missing_input(self):
        """Test validation with missing input"""
        response = self.frontend_client.post(
            "/validate-input",
            json={"security_level": "high"}
        )
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
