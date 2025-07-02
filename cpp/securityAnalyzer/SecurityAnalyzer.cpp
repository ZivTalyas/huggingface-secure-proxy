#include "SecurityAnalyzer.h"
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <boost/regex.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <iostream>
#include <algorithm>

// Regular expressions for PII detection
const boost::regex email_pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
// Very strict phone pattern: require clear phone number formatting with proper separators
const boost::regex phone_pattern(R"(\b(?:\+1[\s\-\.]?)?(?:\([2-9]\d{2}\)[\s\-\.]?|[2-9]\d{2}[\s\-\.])[2-9]\d{2}[\s\-\.]\d{4}\b|\b(?:\+\d{1,3}[\s\-\.])?(?:\d{3}[\s\-\.]\d{3}[\s\-\.]\d{4})\b)");
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
    
    // Convert to lowercase for case-insensitive matching
    std::string text_lower = text;
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
    
    // SQL Injection patterns (comprehensive)
    std::vector<std::string> sql_patterns = {
        "' or '", "' or 1=1", "' or 1=1--", "' or '1'='1", "' or \"1\"=\"1",
        "' union select", "union all select", "' having '", "' group by '",
        "' order by ", "' drop table", "'; drop table", "' delete from", "' insert into",
        "' update ", "' alter table", "' create table", "' truncate ",
        "'; exec", "'; execute", "xp_cmdshell", "sp_executesql",
        "benchmark(", "sleep(", "waitfor delay", "pg_sleep(",
        "extractvalue(", "updatexml(", "load_file(", "into outfile",
        "information_schema", "mysql.user", "sysobjects", "syscolumns"
    };
    
    for (const auto& pattern : sql_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential SQL injection attempt detected");
            break;
        }
    }
    
    // XSS/JavaScript injection patterns (comprehensive)
    std::vector<std::string> xss_patterns = {
        "<script", "</script>", "javascript:", "vbscript:", "onload=", "onerror=",
        "onclick=", "onmouseover=", "onfocus=", "onblur=", "onchange=",
        "onsubmit=", "onreset=", "onkeydown=", "onkeyup=", "onkeypress=",
        "document.cookie", "document.write", "window.location", "eval(",
        "settimeout(", "setinterval(", "innerhtml=", "outerhtml=",
        "document.getelementbyid", "alert(", "confirm(", "prompt(",
        "fromcharcode(", "unescape(", "string.fromcharcode"
    };
    
    for (const auto& pattern : xss_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential XSS attack detected");
            break;
        }
    }
    
    // Command injection patterns (comprehensive)
    std::vector<std::string> cmd_patterns = {
        "; rm -rf", "; del ", "& echo", "| nc ", "| netcat", "; wget",
        "; curl", "; cat /etc/passwd", "; cat /etc/shadow", "$(", "`",
        "; ls -la", "; dir", "; whoami", "; id", "; uname", "; ps aux",
        "; netstat", "; ifconfig", "; ping", "; nslookup", "; dig",
        "; chmod +x", "; ./", "&&", "||", "; sh", "; bash", "; cmd",
        "; powershell", "& type", "& copy", "& move", "& ren"
    };
    
    for (const auto& pattern : cmd_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential command injection attempt detected");
            break;
        }
    }
    
    // NoSQL injection patterns
    std::vector<std::string> nosql_patterns = {
        "$where", "$ne", "$in", "$nin", "$regex", "$exists", "$elemMatch",
        "$gt", "$gte", "$lt", "$lte", "$or", "$and", "$not", "$nor",
        "this.password", "this.username", "db.eval", "mapreduce",
        "return true", "return false", "; return ", "var x=", "var y="
    };
    
    for (const auto& pattern : nosql_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential NoSQL injection attempt detected");
            break;
        }
    }
    
    // LDAP injection patterns
    std::vector<std::string> ldap_patterns = {
        ")(cn=*", ")(uid=*", ")(mail=*", ")(&", ")(|", "*)(uid=*",
        "*)(cn=*", "admin*", "*admin", ")(objectclass=*"
    };
    
    for (const auto& pattern : ldap_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential LDAP injection attempt detected");
            break;
        }
    }
    
    // Path traversal patterns
    std::vector<std::string> path_patterns = {
        "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "....//", "....\\\\",
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\windows\\system32",
        "boot.ini", "web.config", ".env", ".htaccess", "/proc/self/environ"
    };
    
    for (const auto& pattern : path_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential path traversal attempt detected");
            break;
        }
    }
    
    // XML/XXE injection patterns
    std::vector<std::string> xml_patterns = {
        "<!entity", "<!doctype", "system \"file://", "system \"http://",
        "system \"ftp://", "%xxe;", "&xxe;", "xml version=", "<?xml"
    };
    
    for (const auto& pattern : xml_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential XML/XXE injection attempt detected");
            break;
        }
    }
    
    // Template injection patterns
    std::vector<std::string> template_patterns = {
        "{{", "}}", "${", "#{", "<%", "%>", "@{", "[[", "]]",
        "__import__", "getattr(", "setattr(", "__builtins__",
        "exec(", "eval(", "compile(", "__globals__"
    };
    
    for (const auto& pattern : template_patterns) {
        if (text.find(pattern) != std::string::npos) {
            issues.push_back("Potential template injection attempt detected");
            break;
        }
    }
    
    // Code execution function patterns (comprehensive)
    std::vector<std::string> exec_patterns = {
        // PHP functions
        "system(", "exec(", "shell_exec(", "passthru(", "popen(",
        "proc_open(", "eval(", "base64_decode", "file_get_contents(",
        "fopen(", "fwrite(", "unlink(", "chmod(", "chown(", "mkdir(",
        "rmdir(", "symlink(", "readfile(", "include(", "require(",
        "preg_replace(", "create_function(", "call_user_func(",
        
        // Python functions
        "__import__(", "getattr(", "setattr(", "hasattr(", "delattr(",
        "globals(", "locals(", "vars(", "dir(", "compile(", "execfile(",
        "input(", "raw_input(", "open(", "file(", "__builtins__",
        
        // JavaScript functions
        "function(", "new function", "constructor(", "apply(", "call(",
        "bind(", "with(", "delete ", "void(", "typeof ",
        
        // System commands
        "cmd.exe", "/bin/sh", "/bin/bash", "powershell.exe", "sh.exe",
        "bash.exe", "python.exe", "perl.exe", "ruby.exe", "java.exe",
        
        // Network functions
        "curl(", "wget(", "fetch(", "xmlhttprequest", "ajax(",
        "socket(", "connect(", "bind(", "listen(", "accept("
    };
    
    for (const auto& pattern : exec_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Potential code execution attempt detected: " + pattern);
        }
    }
    
    // Additional suspicious patterns
    std::vector<std::string> suspicious_patterns = {
        "base64", "hex2bin", "bin2hex", "rot13", "str_rot13",
        "gzinflate(", "gzuncompress(", "bzdecompress(",
        "mcrypt_decrypt(", "openssl_decrypt(", "password_verify(",
        "crypt(", "md5(", "sha1(", "hash(", "hash_hmac("
    };
    
    for (const auto& pattern : suspicious_patterns) {
        if (text_lower.find(pattern) != std::string::npos) {
            issues.push_back("Suspicious function detected: " + pattern);
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
        
        // Debug: Log extracted text content (first 200 chars)
        std::cout << "DEBUG: Extracted PDF text (first 200 chars): " 
                  << text_content.substr(0, std::min(200UL, text_content.length())) << std::endl;
        
        // Analyze extracted text using the same method as text files
        result = analyzeText(text_content);
        
        // Update analysis summary to indicate PDF processing
        result.analysis_summary = std::string("PDF analysis completed. ") + 
            (result.is_safe ? "No security issues detected in extracted text." : 
             "Potential security issues identified in extracted text.");
        
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