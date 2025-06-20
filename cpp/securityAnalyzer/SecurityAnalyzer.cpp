#include "security_cpp.h"
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <regex>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <nlohmann/json.hpp>

// Regular expressions for PII detection
const std::regex email_pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
const std::regex phone_pattern(R"(\+?[1-9]\d{1,14})");
const std::regex ssn_pattern(R"(\b\d{3}-\d{2}-\d{4}\b)");

// Security thresholds
const double DEFAULT_THRESHOLD = 0.8;
const int MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Initialize ML model paths
const std::string SECURITY_MODEL_PATH = "/models/security_classifier.onnx";

AnalysisResult SecurityAnalyzer::analyzeText(const std::string& text) {
    AnalysisResult result;
    
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
    result.is_safe = result.confidence_score >= DEFAULT_THRESHOLD;
    
    // Generate analysis summary
    result.analysis_summary = "Text analysis completed. "
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
        "link(",
        "exec(",
        "system(",
        "passthru(",
        "shell_exec(",
        "popen(",
        "proc_open(",
        "curl_exec(",
        "file_put_contents(",
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
        "link(",
        "exec(",
        "system(",
        "passthru(",
        "shell_exec(",
        "popen(",
        "proc_open(",
        "curl_exec(",
        "file_put_contents(",
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
        "link(",
        "exec(",
        "system(",
        "passthru(",
        "shell_exec(",
        "popen(",
        "proc_open(",
        "curl_exec(",
        "file_put_contents(",
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
        "link(")
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
        // Load and extract text from PDF
        auto doc = loadPDF(pdf_data);
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
            
            // Check for JavaScript
            if (doc->has_javascript()) {
                result.detected_issues.push_back("PDF contains JavaScript");
                result.confidence_score *= 0.7;  // Reduce confidence
            }
        }
        
        result.is_safe = result.confidence_score >= DEFAULT_THRESHOLD;
        
    } catch (const std::exception& e) {
        result.is_safe = false;
        result.detected_issues.push_back("Error processing PDF: " + std::string(e.what()));
    }
    
    return result;
}

std::vector<std::string> SecurityAnalyzer::detectPII(const std::string& text) {
    std::vector<std::string> issues;
    
    // Detect emails
    std::smatch email_matches;
    if (std::regex_search(text, email_matches, email_pattern)) {
        issues.push_back("Email address detected");
    }
    
    // Detect phone numbers
    std::smatch phone_matches;
    if (std::regex_search(text, phone_matches, phone_pattern)) {
        issues.push_back("Phone number detected");
    }
    
    // Detect SSN
    std::smatch ssn_matches;
    if (std::regex_search(text, ssn_matches, ssn_pattern)) {
        issues.push_back("Social Security Number detected");
    }
    
    return issues;
}

double SecurityAnalyzer::calculateSafetyScore(const std::string& text) {
    // Load ML model if not already loaded
    if (!model) {
        loadModel(SECURITY_MODEL_PATH);
    }
    
    // Extract features
    std::vector<float> features = extractFeatures(text);
    
    // Get prediction
    MLInference::ModelPrediction prediction = predict(features);
    
    return prediction.confidence;
}

std::string TextProcessor::extractTextFromPDF(const std::vector<uint8_t>& pdf_data) {
    auto doc = std::make_unique<poppler::document>(
        reinterpret_cast<const unsigned char*>(pdf_data.data()),
        pdf_data.size(),
        nullptr
    );
    
    std::string text;
    for (int i = 0; i < doc->pages(); ++i) {
        auto page = doc->create_page(i);
        text += page->text() + "\n";
    }
    
    return text;
}

std::string TextProcessor::cleanText(const std::string& raw_text) {
    std::string text = raw_text;
    
    // Remove special characters
    text = removeSpecialCharacters(text);
    
    // Normalize text
    text = normalizeText(text);
    
    return text;
}

std::vector<std::string> TextProcessor::tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    boost::split(tokens, text, boost::is_any_of(" "), boost::token_compress_on);
    return tokens;
}

bool TextProcessor::detectPII(const std::string& text) {
    return !detectPII(text).empty();
}
