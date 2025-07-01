#!/usr/bin/env python3
"""
Debug script to test the C++ SecurityAnalyzer directly to understand 
why it's detecting phone numbers in the Tel Aviv PDF.
"""
import sys
import os
import base64
from pathlib import Path

# Add the app directory to Python path
sys.path.append(str(Path(__file__).parent / "app"))

try:
    from security import SecurityAnalyzer
    cpp_available = True
    print("✓ C++ SecurityAnalyzer imported successfully")
except ImportError as e:
    print(f"✗ Failed to import C++ SecurityAnalyzer: {e}")
    cpp_available = False

def test_with_cpp_analyzer():
    """Test the PDF using the actual C++ SecurityAnalyzer"""
    if not cpp_available:
        print("Cannot test - C++ module not available")
        return
    
    pdf_path = "test_files/Tel_Aviv_clean.pdf"
    
    if not os.path.exists(pdf_path):
        print(f"PDF file not found: {pdf_path}")
        return
    
    print(f"Testing PDF: {pdf_path}")
    print("=" * 60)
    
    # Create analyzer with different thresholds
    for threshold in [0.5, 0.7, 0.9]:
        print(f"\nTesting with threshold {threshold}:")
        print("-" * 40)
        
        analyzer = SecurityAnalyzer(threshold=threshold)
        
        try:
            # Test file analysis (this should use C++ PDF extraction)
            result = analyzer.analyze_file(pdf_path)
            
            print(f"Result: {result}")
            print(f"Is safe: {result.get('is_safe', 'unknown')}")
            print(f"Confidence: {result.get('confidence_score', 'unknown')}")
            print(f"Issues: {result.get('detected_issues', [])}")
            print(f"Summary: {result.get('analysis_summary', 'none')}")
            
        except Exception as e:
            print(f"Error analyzing file: {e}")
            import traceback
            traceback.print_exc()

def test_with_base64():
    """Test using base64 content like the API does"""
    if not cpp_available:
        print("Cannot test - C++ module not available")
        return
    
    pdf_path = "test_files/Tel_Aviv_clean.pdf"
    
    print(f"\nTesting base64 approach (like API):")
    print("=" * 60)
    
    # Read and encode file
    with open(pdf_path, 'rb') as f:
        content = f.read()
    
    base64_content = base64.b64encode(content).decode('utf-8')
    
    # Import SecurityService (which processes base64)
    try:
        from security.service import SecurityService
        
        service = SecurityService(security_level="high")
        result = service.validate_file(base64_content)
        
        print(f"SecurityService result: {result}")
        
    except Exception as e:
        print(f"Error with SecurityService: {e}")
        import traceback
        traceback.print_exc()

def main():
    print("Debugging C++ SecurityAnalyzer phone number detection")
    print("=" * 60)
    
    test_with_cpp_analyzer()
    test_with_base64()

if __name__ == "__main__":
    main() 