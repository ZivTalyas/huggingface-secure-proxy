#include "SecurityAnalyzer.h"
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <boost/regex.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>

// Regular expressions for PII detection
const boost::regex email_pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
// Require common phone number patterns with separators; at least 7 digits overall
const boost::regex phone_pattern(R"((?:\+?\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?)?\d{3}[\s-]?\d{3,4}\b)" );
const boost::regex ssn_pattern(R"(\b\d{3}-\d{2}-\d{4}\b)");

// Security thresholds
const double DEFAULT_THRESHOLD = 0.8;
const int MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Constructor
SecurityAnalyzer::SecurityAnalyzer(double threshold) : threshold_(threshold) {}

void SecurityAnalyzer::setThreshold(double threshold) {
    threshold_ = threshold;
}

double SecurityAnalyzer::getThreshold() const {
    return threshold_;
}

AnalysisResult SecurityAnalyzer::analyzeText(const std::string& text) {
    AnalysisResult result;
    
    // size guard so text files follow same 10 MB limit as PDFs
    if (text.size() > MAX_FILE_SIZE) {
        result.is_safe = false;
        result.confidence_score = 0.0;
        result.detected_issues.push_back("File size exceeds maximum allowed size");
        result.analysis_summary = "Text exceeds maximum allowed size";
        return result;
    }
    
    // Check for PII
    std::vector<std::string> pii_issues = detectPII(text);
    if (!pii_issues.empty()) {
        result.detected_issues.insert(result.detected_issues.end(), pii_issues.begin(), pii_issues.end());
    }
    
    // Check for malicious content
    std::vector<std::string> malicious_issues = detectMaliciousContent(text);
    if (!malicious_issues.empty()) {
        result.detected_issues.insert(result.detected_issues.end(), malicious_issues.begin(), malicious_issues.end());
    }
    
    // Calculate safety score
    result.confidence_score = calculateSafetyScore(text);
    result.is_safe = result.confidence_score >= threshold_;
    
    // Generate analysis summary
    result.analysis_summary = std::string("Text analysis completed. ")
        + (result.is_safe ? "No security issues detected." : "Potential security issues identified.");
    
    return result;
}

std::vector<std::string> SecurityAnalyzer::detectMaliciousContent(const std::string& text) {
    std::vector<std::string> issues;
    
    // Check for SQL injection patterns
    if (text.find("' OR '") != std::string::npos ||
        text.find("' OR 1=1") != std::string::npos ||
        text.find("' OR 1=1--") != std::string::npos) {
        issues.push_back("Potential SQL injection attempt detected");
    }
    
    // Check for XSS patterns
    if (text.find("<script>") != std::string::npos ||
        text.find("javascript:") != std::string::npos ||
        text.find("onload=") != std::string::npos) {
        issues.push_back("Potential XSS attack detected");
    }
    
    // Check for command injection patterns
    if (text.find("; rm -rf") != std::string::npos ||
        text.find("; del ") != std::string::npos ||
        text.find("& echo") != std::string::npos) {
        issues.push_back("Potential command injection attempt detected");
    }
    
    // Check for common malware signatures
    std::vector<std::string> malware_patterns = {
        "base64_decode",
        "eval(base64",
        "system(",
        "exec(",
        "shell_exec(",
        "passthru(",
        "popen(",
        "proc_open(",
        "curl_exec(",
        "file_get_contents(",
        "fopen(",
        "fwrite(",
        "unlink(",
        "chmod(",
        "chown(",
        "chgrp(",
        "rename(",
        "move_uploaded_file(",
        "copy(",
        "mkdir(",
        "rmdir(",
        "unlink(",
        "symlink(",
        "link("
    };
    
    for (const auto& pattern : malware_patterns) {
        if (text.find(pattern) != std::string::npos) {
            issues.push_back("Potential malware signature detected: " + pattern);
        }
    }
    
    return issues;
}

AnalysisResult SecurityAnalyzer::analyzePDF(const std::vector<uint8_t>& pdf_data) {
    AnalysisResult result;
    
    // Check file size
    if (pdf_data.size() > MAX_FILE_SIZE) {
        result.is_safe = false;
        result.detected_issues.push_back("File size exceeds maximum allowed size");
        return result;
    }
    
    try {
        // Load PDF
        auto doc = loadPDF(pdf_data);

        if (!doc) {
            result.is_safe = false;
            result.detected_issues.push_back("invalid_or_corrupted_pdf");
            return result;
        }

        // Extract text
        std::string text_content = extractTextFromPDF(doc);
        
        // Analyze extracted text
        result = analyzeText(text_content);
        
        // Add PDF-specific analysis
        if (result.is_safe) {
            // Check for embedded scripts
            if (doc->has_embedded_files()) {
                result.detected_issues.push_back("PDF contains embedded files");
                result.confidence_score *= 0.8;  // Reduce confidence
            }
        }
        
        result.is_safe = result.confidence_score >= threshold_;
        
    } catch (const std::exception& e) {
        result.is_safe = false;
        result.detected_issues.push_back("Error processing PDF: " + std::string(e.what()));
    }
    
    return result;
}

std::vector<std::string> SecurityAnalyzer::detectPII(const std::string& text) {
    std::vector<std::string> issues;
    
    boost::smatch email_matches;
    if (boost::regex_search(text, email_matches, email_pattern)) {
        issues.push_back("Email address detected");
    }
    
    boost::smatch phone_matches;
    if (boost::regex_search(text, phone_matches, phone_pattern)) {
        issues.push_back("Phone number detected");
    }
    
    boost::smatch ssn_matches;
    if (boost::regex_search(text, ssn_matches, ssn_pattern)) {
        issues.push_back("Social Security Number detected");
    }
    
    // If any PII issues were found, add a generic flag as well for convenience
    if (!issues.empty()) {
        issues.insert(issues.begin(), "PII detected");
    }
    
    return issues;
}

double SecurityAnalyzer::calculateSafetyScore(const std::string& text) {
    double score = 1.0;

    if (!detectMaliciousContent(text).empty()) {
        score -= 0.5;
    }

    if (!detectPII(text).empty()) {
        score -= 0.5;
    }

    return score;
}

bool SecurityAnalyzer::isContentSafe(const std::string& content, double threshold) {
    AnalysisResult result = analyzeText(content);
    return result.is_safe && result.confidence_score >= threshold;
}

std::unique_ptr<poppler::document> SecurityAnalyzer::loadPDF(const std::vector<uint8_t>& pdf_data) {
    return std::unique_ptr<poppler::document>(poppler::document::load_from_raw_data(
        reinterpret_cast<const char*>(pdf_data.data()), pdf_data.size()
    ));
}

std::string SecurityAnalyzer::extractTextFromPDF(const std::unique_ptr<poppler::document>& doc) {
    if (!doc) {
        return "";
    }
    
    std::string text;
    for (int i = 0; i < doc->pages(); ++i) {
        std::unique_ptr<poppler::page> page(doc->create_page(i));
        if (page) {
            text += page->text().to_latin1();
        }
    }
    return text;
} 