#pragma once

#include <string>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include "textProcessor/TextProcessor.h"
#include "mlInterface/MLInference.h"

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
    
    // Dependencies
    TextProcessor text_processor;
    MLInference ml_inference;
};
