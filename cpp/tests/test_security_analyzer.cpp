#include <gtest/gtest.h>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
