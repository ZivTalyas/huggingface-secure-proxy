"""
Security module for input validation and analysis.
This module provides a Python interface to the C++ security analyzer.
If the C++ module is not available, it falls back to a pure Python implementation.
"""
import os
import ctypes
import platform
import logging
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to load the C++ module
try:
    if platform.system() == 'Windows':
        lib_name = 'security_analyzer.dll'
    elif platform.system() == 'Darwin':
        lib_name = 'libsecurity_analyzer.dylib'
    else:  # Linux and others
        lib_name = 'libsecurity_analyzer.so'
    
    # Use ctypes.util.find_library to search for the library in system paths
    lib_path_str = ctypes.util.find_library('security_analyzer')
    if not lib_path_str:
        # As a fallback, check the directory of this file
        local_lib_path = Path(__file__).parent / lib_name
        if local_lib_path.exists():
            lib_path_str = str(local_lib_path)
        else:
            raise ImportError(f"Could not find {lib_name} in system paths or local directory.")

    _lib = ctypes.CDLL(lib_path_str)
    
    # Define the function signatures
    _lib.analyze_text.argtypes = [ctypes.c_char_p]
    _lib.analyze_text.restype = ctypes.c_void_p
    
    _lib.analyze_pdf.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
    _lib.analyze_pdf.restype = ctypes.c_void_p
    
    _lib.free_result.argtypes = [ctypes.c_void_p]
    _lib.free_result.restype = None
    
    _lib.is_content_safe.argtypes = [ctypes.c_char_p, ctypes.c_double]
    _lib.is_content_safe.restype = ctypes.c_bool
    
    _cpp_available = True
    logger.info("C++ security analyzer module loaded successfully.")
except Exception as e:
    _cpp_available = False
    _import_error = str(e)
    logger.warning(f"C++ security analyzer not available: {_import_error}. Using Python fallback.")


class SecurityAnalyzer:
    """
    Provides security analysis for text and files.
    Uses a C++ backend if available, otherwise falls back to a Python implementation.
    """
    
    def __init__(self):
        """Initializes the SecurityAnalyzer."""
        # The constructor no longer raises an error.
        # The availability of the C++ module is handled by each method.
        pass
    
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Analyze text for security issues."""
        if not _cpp_available:
            return self._fallback_analyze_text(text)
            
        result_ptr = _lib.analyze_text(text.encode('utf-8'))
        if not result_ptr:
            logger.error("C++ analyze_text returned a null pointer.")
            return self._fallback_analyze_text(text)
            
        result = self._parse_result(result_ptr)
        _lib.free_result(result_ptr)
        return result
    
    def analyze_file(self, file_path: Union[str, os.PathLike]) -> Dict[str, Any]:
        """Analyze a file for security issues."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        if not _cpp_available:
            return self._fallback_analyze_file(file_path)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        data_array = (ctypes.c_ubyte * len(data))(*data)
        result_ptr = _lib.analyze_pdf(data_array, len(data))
        if not result_ptr:
            logger.error(f"C++ analyze_pdf returned a null pointer for file: {file_path}")
            return self._fallback_analyze_file(file_path)
        
        result = self._parse_result(result_ptr)
        _lib.free_result(result_ptr)
        return result
    
    def is_content_safe(self, content: str, threshold: float = 0.8) -> bool:
        """Check if content is safe based on a confidence threshold."""
        if not _cpp_available:
            return self._fallback_is_content_safe(content, threshold)
        return _lib.is_content_safe(content.encode('utf-8'), threshold)
    
    def _parse_result(self, result_ptr: int) -> Dict[str, Any]:
        """Parses the JSON string result from the C++ library."""
        # Assuming the C++ function returns a char* (string) that needs to be freed.
        # This part needs to be implemented based on the actual C++ return type.
        # For now, we'll assume it returns a JSON string.
        # This is a placeholder.
        return {
            'is_safe': True,
            'confidence_score': 1.0,
            'detected_issues': [],
            'analysis_summary': 'Analysis performed by C++ module (mocked parsing).'
        }
    
    def _fallback_analyze_text(self, text: str) -> Dict[str, Any]:
        """Fallback text analysis when C++ module is not available."""
        issues = []
        if any(char in text for char in [';', '--', '/*', '*/', 'xp_', 'UNION', 'SELECT']):
            issues.append('potential_sql_injection')
        if '<script>' in text.lower():
            issues.append('potential_xss')
        return {
            'is_safe': not issues,
            'confidence_score': 0.5 if issues else 1.0,
            'detected_issues': issues,
            'analysis_summary': 'Fallback analysis - limited capabilities'
        }
    
    def _fallback_analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Fallback file analysis when C++ module is not available."""
        if file_path.suffix.lower() not in ['.txt', '.pdf']:
            return {
                'is_safe': False,
                'confidence_score': 0.8,
                'detected_issues': ['unsupported_file_type'],
                'analysis_summary': f'Unsupported file type: {file_path.suffix}'
            }
        if file_path.suffix.lower() == '.txt':
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                return self._fallback_analyze_text(content)
            except Exception as e:
                logger.error(f"Error reading text file in fallback mode: {e}")
                return {'is_safe': False, 'detected_issues': ['file_read_error']}

        return {
            'is_safe': True,
            'confidence_score': 0.5,
            'detected_issues': [],
            'analysis_summary': 'PDF analysis requires the C++ module, skipping.'
        }
    
    def _fallback_is_content_safe(self, content: str, threshold: float) -> bool:
        """Fallback safety check when C++ module is not available."""
        result = self._fallback_analyze_text(content)
        return result['confidence_score'] >= threshold

# This default instance can be used for simple checks.
default_analyzer = SecurityAnalyzer()

def is_content_safe(content: str, threshold: float = 0.8) -> bool:
    """Convenience function to check if content is safe."""
    return default_analyzer.is_content_safe(content, threshold)
