#pragma once

#include <string>
#include <vector>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

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
