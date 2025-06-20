#include "TextProcessor.h"
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <regex>

// Regular expressions for PII detection
const std::regex email_pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
const std::regex phone_pattern(R"(\+?[1-9]\d{1,14})");

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

std::string TextProcessor::removeSpecialCharacters(const std::string& text) {
    std::string result;
    for (char c : text) {
        if (isalnum(c) || c == ' ' || c == '.' || c == ',') {
            result += c;
        }
    }
    return result;
}

std::string TextProcessor::normalizeText(const std::string& text) {
    std::string result = text;
    boost::to_lower(result);
    boost::trim(result);
    return result;
}

std::vector<std::string> TextProcessor::extractEmails(const std::string& text) {
    std::vector<std::string> emails;
    std::smatch matches;
    
    while (std::regex_search(text, matches, email_pattern)) {
        emails.push_back(matches[0]);
        text = matches.suffix().str();
    }
    
    return emails;
}

std::vector<std::string> TextProcessor::extractPhoneNumbers(const std::string& text) {
    std::vector<std::string> numbers;
    std::smatch matches;
    
    while (std::regex_search(text, matches, phone_pattern)) {
        numbers.push_back(matches[0]);
        text = matches.suffix().str();
    }
    
    return numbers;
}
