#include <gtest/gtest.h>
#include <fstream>
#include <vector>
#include <filesystem>
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
        createTestFile("sensitive.txt", "Please find my credit card: 4111-1111-1111-1111");
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
    auto result = analyzer.analyzeText("My credit card is 4111-1111-1111-1111");
    EXPECT_FALSE(result.is_safe);
    bool has_pii = std::find(result.detected_issues.begin(), 
                           result.detected_issues.end(), 
                           "pii_detected") != result.detected_issues.end();
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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
