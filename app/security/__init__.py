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
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
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
            self.cpp_analyzer = CppSecurityAnalyzer(threshold)
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
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
            if self.gemini_api_key else None
        )

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyzes text using Python-based keyword and LLM checks."""
        issues: List[str] = []
        
        # Rule-based keyword checks
        if any(keyword.lower() in text.lower() for keyword in self.harmful_keywords):
            issues.append('harmful_keyword_detected')
        
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
            'analysis_summary': 'Python-based text analysis (Keywords + LLM)'
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
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # The C++ module expects bytes and returns an AnalysisResult object
        result: AnalysisResult = self.cpp_analyzer.analyze_pdf(data)
        
        # Convert the C++ result object to a dictionary
        return {
            'is_safe': result.is_safe,
            'confidence_score': result.confidence_score,
            'detected_issues': list(result.detected_issues),
            'analysis_summary': result.analysis_summary
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
