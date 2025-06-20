#pragma once

#include <string>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>

// Forward declarations
namespace poppler {
    class document;
}

class SecurityAnalyzer {
public:
    struct AnalysisResult {
        bool is_safe;
        double confidence_score;
        std::vector<std::string> detected_issues;
        std::string analysis_summary;
    };
    
    AnalysisResult analyzeText(const std::string& text);
    AnalysisResult analyzePDF(const std::vector<uint8_t>& pdf_data);
    bool isContentSafe(const std::string& content, double threshold = 0.8);
    
private:
    std::unique_ptr<poppler::document> loadPDF(const std::vector<uint8_t>& pdf_data);
    std::string extractTextFromPDF(const std::unique_ptr<poppler::document>& doc);
    std::vector<std::string> detectPII(const std::string& text);
    std::vector<std::string> detectMaliciousContent(const std::string& text);
    double calculateSafetyScore(const std::string& text);
};

class TextProcessor {
public:
    std::string extractTextFromPDF(const std::vector<uint8_t>& pdf_data);
    std::string cleanText(const std::string& raw_text);
    std::vector<std::string> tokenize(const std::string& text);
    bool detectPII(const std::string& text);
    
private:
    std::string removeSpecialCharacters(const std::string& text);
    std::string normalizeText(const std::string& text);
    std::vector<std::string> extractEmails(const std::string& text);
    std::vector<std::string> extractPhoneNumbers(const std::string& text);
};

class MLInference {
public:
    struct ModelPrediction {
        std::string label;
        double confidence;
        std::map<std::string, double> scores;
    };
    
    bool loadModel(const std::string& model_path);
    ModelPrediction predict(const std::vector<float>& features);
    std::vector<float> extractFeatures(const std::string& text);
    
private:
    std::unique_ptr<nlohmann::json> model;
};
