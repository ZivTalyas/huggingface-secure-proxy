import unittest
import os
import json
import base64
import requests

# Base URL of the running proxy (can be overridden when executing tests)
BASE_URL = os.getenv("PROXY_BASE_URL", "http://localhost:8000")

class TestSecureInputProxy(unittest.TestCase):    
    def setUp(self):
        # Base URL for requests
        self.base_url = BASE_URL

        # Skip all tests if server not running
        try:
            requests.get(f"{self.base_url}/status", timeout=2)
        except requests.RequestException:
            raise unittest.SkipTest(f"API server not reachable at {self.base_url}; start the stack before running these tests.")

        # Test data
        self.safe_text = "Hello, this is a safe message."
        self.unsafe_text = "You're so dumb it's funny."
        self.test_file_content = b"This is a test file content."
        self.test_file_b64 = base64.b64encode(self.test_file_content).decode('utf-8')
    
    def test_frontend_health(self):
        """Test frontend health check endpoint"""
        response = requests.get(f"{self.base_url}/status", timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.json())
    
    
    def test_validate_safe_text(self):
        """Test validation of safe text input"""
        response = requests.post(f"{self.base_url}/validate-input",
            json={"text": self.safe_text, "security_level": "high"}
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "safe")
    
    def test_validate_unsafe_text(self):
        """Test validation of unsafe text input"""
        response = requests.post(f"{self.base_url}/validate-input",
            json={"text": self.unsafe_text, "security_level": "high"}
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "unsafe")
    
    def test_validate_file_upload_txt(self):
        """Test file validation with .txt file using multipart/form-data"""
        sample_txt_path = "sample_test_file.txt"
        with open(sample_txt_path, "w") as f:
            f.write("Sample text file for validation.")
        with open(sample_txt_path, "rb") as f:
            files = {"file": (sample_txt_path, f, "text/plain")}
            data = {"security_level": "high"}
            response = requests.post(f"{self.base_url}/validate-input", data=data, files=files)
        os.remove(sample_txt_path)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)

    def test_validate_file_upload_pdf(self):
        """Test file validation with .pdf file using multipart/form-data"""
        sample_pdf_path = "sample_test_file.pdf"
        with open(sample_pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000067 00000 n \n0000000122 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n177\n%%EOF\n")
        with open(sample_pdf_path, "rb") as f:
            files = {"file": (sample_pdf_path, f, "application/pdf")}
            data = {"security_level": "high"}
            response = requests.post(f"{self.base_url}/validate-input", data=data, files=files)
        os.remove(sample_pdf_path)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)
    
    def test_invalid_security_level(self):
        """Test validation with invalid security level"""
        response = requests.post(f"{self.base_url}/validate-input",
            json={"text": self.safe_text, "security_level": "invalid"}
        )
        self.assertEqual(response.status_code, 400)
    
    def test_missing_input(self):
        """Test validation with missing input"""
        response = requests.post(f"{self.base_url}/validate-input",
            json={"security_level": "high"}
        )
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
