#!/usr/bin/env python3
"""
Debug script to test phone number detection against the Tel Aviv PDF content.
"""
import re
import base64
import subprocess
import os

def extract_pdf_text(pdf_path):
    """Extract text from PDF using pdftotext"""
    try:
        result = subprocess.run(['pdftotext', pdf_path, '-'], 
                               capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error extracting PDF text: {e}")
        return ""

def test_phone_patterns(text):
    """Test various phone number regex patterns"""
    patterns = {
        'cpp_original': r'(?:\+?\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?)?\d{3}[\s-]?\d{3,4}\b',
        'strict_phone': r'\+?[\d\s\-\(\)]{7,15}',
        'loose_digits': r'\d{3,4}[\s-]?\d{3,4}',
        'very_loose': r'\d{3,}',
    }
    
    print("Testing phone number patterns:")
    print("=" * 50)
    print(f"Text length: {len(text)}")
    print(f"Text repr: {repr(text[:200])}")
    print("=" * 50)
    
    for name, pattern in patterns.items():
        matches = list(re.finditer(pattern, text))
        print(f"\nPattern '{name}': {pattern}")
        print(f"Matches found: {len(matches)}")
        
        for i, match in enumerate(matches[:5]):  # Show first 5 matches
            start, end = match.span()
            context_start = max(0, start - 20)
            context_end = min(len(text), end + 20)
            print(f"  Match {i+1}: '{match.group()}' at {start}-{end}")
            print(f"  Context: '{text[context_start:context_end]}'")

def main():
    pdf_path = "test_files/Tel_Aviv_clean.pdf"
    
    if not os.path.exists(pdf_path):
        print(f"PDF file not found: {pdf_path}")
        return
    
    # Extract text from PDF
    text = extract_pdf_text(pdf_path)
    
    if not text:
        print("Failed to extract text from PDF")
        return
    
    # Test patterns
    test_phone_patterns(text)
    
    # Also test the specific string "Aviv" and numbers
    print("\n" + "=" * 50)
    print("Testing specific substrings:")
    print("=" * 50)
    
    # Look for any sequences of digits
    digit_sequences = re.findall(r'\d+', text)
    print(f"All digit sequences found: {digit_sequences}")
    
    # Test if "Aviv" might be triggering something
    test_strings = ["Aviv", "Tel Aviv", "22.04"]
    for test_str in test_strings:
        if test_str in text:
            print(f"Found '{test_str}' in text")

if __name__ == "__main__":
    main() 