"""
Security module for input validation and analysis.
This module provides a Python interface to the C++ security analyzer for file analysis,
and a Python-based analyzer for text analysis.
"""
import logging
from typing import Dict, Any, Union, List
from pathlib import Path
import os
import json
import requests
import re

logger = logging.getLogger(__name__)

# --- C++ Module Loading ---
try:
    from security_analyzer import AnalysisResult, SecurityAnalyzer as CppSecurityAnalyzer
    _cpp_available = True
    logger.info("C++ security analyzer module loaded successfully.")
except ImportError as e:
    _cpp_available = False
    logger.warning(f"C++ security analyzer not available: {e}. File analysis will be limited.")
    class AnalysisResult: pass
    class CppSecurityAnalyzer: pass

# --- Python-based Analyzer Resources ---
_HARMFUL_KEYWORDS: List[str] = []
try:
    _kw_path = Path(__file__).parent / "harmful_keywords.json"
    if _kw_path.exists():
        with open(_kw_path, "r", encoding="utf-8") as _kw_file:
            _HARMFUL_KEYWORDS = json.load(_kw_file)
except Exception as e:
    logger.warning(f"Failed to load harmful_keywords.json: {e}")

_GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
_GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    if _GEMINI_API_KEY else None
)

class SecurityAnalyzer:
    """
    Provides security analysis for text (Python) and files (C++).
    """
    
    def __init__(self, threshold: float = 0.8):
        """Initializes the SecurityAnalyzer.

        Args:
            threshold: Safety threshold for the underlying C++ analyzer (if available).
        """
        # C++ Analyzer
        if _cpp_available:
            self.cpp_analyzer = CppSecurityAnalyzer()  # Default threshold
            if hasattr(self.cpp_analyzer, 'setThreshold'):
                self.cpp_analyzer.setThreshold(threshold)
        else:
            self.cpp_analyzer = None

        # Python Analyzer Resources
        self.harmful_keywords: List[str] = []
        try:
            kw_path = Path(__file__).parent / "harmful_keywords.json"
            if kw_path.exists():
                with open(kw_path, "r", encoding="utf-8") as kw_file:
                    self.harmful_keywords = json.load(kw_file)
        except Exception as e:
            logger.warning(f"Failed to load harmful_keywords.json: {e}")

        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.gemini_endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
            if self.gemini_api_key else None
        )

    def detect_code_injection(self, text: str) -> List[str]:
        """Detect various types of code injection attempts."""
        issues = []
        text_lower = text.lower()
        
        # SQL Injection patterns (comprehensive)
        sql_patterns = [
            "' or '", "' or 1=1", "' or 1=1--", "' or '1'='1", "' or \"1\"=\"1",
            "' union select", "union all select", "' having '", "' group by '",
            "' order by ", "' drop table", "'; drop table", "' delete from", "' insert into",
            "' update ", "' alter table", "' create table", "' truncate ",
            "'; exec", "'; execute", "xp_cmdshell", "sp_executesql",
            "benchmark(", "sleep(", "waitfor delay", "pg_sleep(",
            "extractvalue(", "updatexml(", "load_file(", "into outfile",
            "information_schema", "mysql.user", "sysobjects", "syscolumns"
        ]
        
        for pattern in sql_patterns:
            if pattern in text_lower:
                issues.append("Potential SQL injection attempt detected")
                break
        
        # XSS/JavaScript injection patterns (comprehensive)
        xss_patterns = [
            "<script", "</script>", "javascript:", "vbscript:", "onload=", "onerror=",
            "onclick=", "onmouseover=", "onfocus=", "onblur=", "onchange=",
            "onsubmit=", "onreset=", "onkeydown=", "onkeyup=", "onkeypress=",
            "document.cookie", "document.write", "window.location", "eval(",
            "settimeout(", "setinterval(", "innerhtml=", "outerhtml=",
            "document.getelementbyid", "alert(", "confirm(", "prompt(",
            "fromcharcode(", "unescape(", "string.fromcharcode"
        ]
        
        for pattern in xss_patterns:
            if pattern in text_lower:
                issues.append("Potential XSS attack detected")
                break
        
        # Command injection patterns (comprehensive)
        cmd_patterns = [
            "; rm -rf", "; del ", "& echo", "| nc ", "| netcat", "; wget",
            "; curl", "; cat /etc/passwd", "; cat /etc/shadow", "$(", "`",
            "; ls -la", "; dir", "; whoami", "; id", "; uname", "; ps aux",
            "; netstat", "; ifconfig", "; ping", "; nslookup", "; dig",
            "; chmod +x", "; ./", "&&", "||", "; sh", "; bash", "; cmd",
            "; powershell", "& type", "& copy", "& move", "& ren"
        ]
        
        for pattern in cmd_patterns:
            if pattern in text_lower:
                issues.append("Potential command injection attempt detected")
                break
        
        # NoSQL injection patterns
        nosql_patterns = [
            "$where", "$ne", "$in", "$nin", "$regex", "$exists", "$elemmatch",
            "$gt", "$gte", "$lt", "$lte", "$or", "$and", "$not", "$nor",
            "this.password", "this.username", "db.eval", "mapreduce",
            "return true", "return false", "; return ", "var x=", "var y="
        ]
        
        for pattern in nosql_patterns:
            if pattern in text_lower:
                issues.append("Potential NoSQL injection attempt detected")
                break
        
        # LDAP injection patterns
        ldap_patterns = [
            ")(cn=*", ")(uid=*", ")(mail=*", ")(&", ")(|", "*)(uid=*",
            "*)(cn=*", "admin*", "*admin", ")(objectclass=*"
        ]
        
        for pattern in ldap_patterns:
            if pattern in text_lower:
                issues.append("Potential LDAP injection attempt detected")
                break
        
        # Path traversal patterns
        path_patterns = [
            "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "....//", "....\\\\",
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\windows\\system32",
            "boot.ini", "web.config", ".env", ".htaccess", "/proc/self/environ"
        ]
        
        for pattern in path_patterns:
            if pattern in text_lower:
                issues.append("Potential path traversal attempt detected")
                break
        
        # XML/XXE injection patterns
        xml_patterns = [
            "<!entity", "<!doctype", "system \"file://", "system \"http://",
            "system \"ftp://", "%xxe;", "&xxe;", "xml version=", "<?xml"
        ]
        
        for pattern in xml_patterns:
            if pattern in text_lower:
                issues.append("Potential XML/XXE injection attempt detected")
                break
        
        # Template injection patterns (case-sensitive for some)
        template_patterns = [
            "{{", "}}", "${", "#{", "<%", "%>", "@{", "[[", "]]",
            "__import__", "getattr(", "setattr(", "__builtins__",
            "exec(", "eval(", "compile(", "__globals__"
        ]
        
        for pattern in template_patterns:
            if pattern in text:  # Case-sensitive check for template patterns
                issues.append("Potential template injection attempt detected")
                break
        
        # Code execution function patterns (comprehensive)
        exec_patterns = [
            # PHP functions
            "system(", "exec(", "shell_exec(", "passthru(", "popen(",
            "proc_open(", "eval(", "base64_decode", "file_get_contents(",
            "fopen(", "fwrite(", "unlink(", "chmod(", "chown(", "mkdir(",
            "rmdir(", "symlink(", "readfile(", "include(", "require(",
            "preg_replace(", "create_function(", "call_user_func(",
            
            # Python functions
            "__import__(", "getattr(", "setattr(", "hasattr(", "delattr(",
            "globals(", "locals(", "vars(", "dir(", "compile(", "execfile(",
            "input(", "raw_input(", "open(", "file(", "__builtins__",
            
            # JavaScript functions
            "function(", "new function", "constructor(", "apply(", "call(",
            "bind(", "with(", "delete ", "void(", "typeof ",
            
            # System commands
            "cmd.exe", "/bin/sh", "/bin/bash", "powershell.exe", "sh.exe",
            "bash.exe", "python.exe", "perl.exe", "ruby.exe", "java.exe",
            
            # Network functions
            "curl(", "wget(", "fetch(", "xmlhttprequest", "ajax(",
            "socket(", "connect(", "bind(", "listen(", "accept("
        ]
        
        for pattern in exec_patterns:
            if pattern in text_lower:
                issues.append(f"Potential code execution attempt detected: {pattern}")
        
        # Additional suspicious patterns
        suspicious_patterns = [
            "base64", "hex2bin", "bin2hex", "rot13", "str_rot13",
            "gzinflate(", "gzuncompress(", "bzdecompress(",
            "mcrypt_decrypt(", "openssl_decrypt(", "password_verify(",
            "crypt(", "md5(", "sha1(", "hash(", "hash_hmac("
        ]
        
        for pattern in suspicious_patterns:
            if pattern in text_lower:
                issues.append(f"Suspicious function detected: {pattern}")
        
        return issues

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyzes text using Python-based keyword, code injection, and LLM checks."""
        issues: List[str] = []
        
        # Check for code injection patterns first
        injection_issues = self.detect_code_injection(text)
        if injection_issues:
            issues.extend(injection_issues)
        
        # Rule-based keyword checks with word boundaries to avoid false positives
        text_lower = text.lower()
        for keyword in self.harmful_keywords:
            # Use word boundaries to match whole words only
            pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
            if re.search(pattern, text_lower):
                issues.append('harmful_keyword_detected')
                break  # One match is enough
        
        # LLM-based analysis
        llm_score = 1.0
        if self.gemini_endpoint and text.strip():
            try:
                resp = requests.post(
                    self.gemini_endpoint,
                    params={"key": self.gemini_api_key},
                    json={"contents": [{"parts": [{"text": text}]}]},
                    timeout=10
                )
                if resp.status_code == 200:
                    # Basic check for safety feedback from Gemini
                    response_data = resp.json()
                    # This parsing is a placeholder and depends on the exact Gemini API response structure for safety ratings
                    if "promptFeedback" in response_data and response_data["promptFeedback"]["blockReason"]:
                        issues.append('llm_flagged_unsafe')
                        llm_score = 0.0
                else:
                    logger.warning(f"Gemini API call failed with status {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.error(f"Gemini API call exception: {e}", exc_info=True)

        is_safe = not issues
        return {
            'is_safe': is_safe,
            'confidence_score': llm_score if is_safe else 0.0,
            'detected_issues': issues,
            'analysis_summary': 'Python-based text analysis (Code Injection + Keywords + LLM)'
        }

    def analyze_file(self, file_path: Union[str, os.PathLike]) -> Dict[str, Any]:
        """Analyzes a file using the C++ engine."""
        if not self.cpp_analyzer:
            return {
                'is_safe': False,
                'confidence_score': 0.0,
                'detected_issues': ['file_analysis_unavailable'],
                'analysis_summary': 'C++ module is not available for file analysis.'
            }

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # --- File type detection ---
            is_pdf = data[:4] == b'%PDF'

            if is_pdf:
                try:
                    # Convert bytes to list of integers for C++ function
                    pdf_data_list = list(data)
                    result: AnalysisResult = self.cpp_analyzer.analyze_pdf(pdf_data_list)
                except Exception as e:
                    logger.error(f"C++ PDF analysis failed, falling back to text: {e}")
                    text_content = data.decode('utf-8', errors='ignore')
                    result: AnalysisResult = self.cpp_analyzer.analyze_text(text_content)
            else:
                # Treat as text (assuming UTF-8 or ASCII). Non-UTF8 bytes are ignored.
                text_content = data.decode('utf-8', errors='ignore')
                result: AnalysisResult = self.cpp_analyzer.analyze_text(text_content)

            # Convert the C++ result object to a dictionary
            return {
                'is_safe': result.is_safe,
                'confidence_score': result.confidence_score,
                'detected_issues': list(result.detected_issues),
                'analysis_summary': result.analysis_summary
            }

        except Exception as e:  # Catch C++ or I/O errors
            logger.error(f"C++ file analysis failed: {e}", exc_info=True)
            return {
                'is_safe': False,
                'confidence_score': 0.0,
                'detected_issues': ['file_analysis_error'],
                'analysis_summary': str(e)
            }

    def is_content_safe(self, content: str, threshold: float = 0.8) -> bool:
        """Checks if text content is safe using the Python analyzer."""
        result = self.analyze_text(content)
        return result['is_safe'] and result['confidence_score'] >= threshold

# This default instance can be used for simple checks.
default_analyzer = SecurityAnalyzer()

def is_content_safe(content: str, threshold: float = 0.8) -> bool:
    """Convenience function to check if content is safe."""
    return default_analyzer.is_content_safe(content, threshold)
