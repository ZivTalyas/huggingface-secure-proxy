#include "MLInference.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>

MLInference::MLInference()
    : env(ORT_LOGGING_LEVEL_WARNING, "MLInference"),
      session_options() {
    session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
}

bool MLInference::loadModel(const std::string& model_path) {
    try {
        session = std::make_unique<Ort::Session>(env, model_path.c_str(), session_options);
        return true;
    } catch (const Ort::Exception& e) {
        std::cerr << "Error loading model: " << e.what() << std::endl;
        return false;
    }
}

MLInference::ModelPrediction MLInference::predict(const std::vector<float>& features) {
    ModelPrediction prediction;
    
    if (!session) {
        throw std::runtime_error("Model not loaded");
    }
    
    try {
        // Prepare input tensor
        Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            memory_info,
            features.data(),
            features.size(),
            {1, static_cast<int64_t>(features.size())}
        );
        
        // Run inference
        auto output_names = session->GetOutputNames();
        auto output_tensors = session->Run(
            Ort::RunOptions{nullptr},
            {"input"},
            {input_tensor},
            {output_names[0].c_str()}
        );
        
        // Process output
        auto output_tensor = output_tensors[0];
        auto output_data = output_tensor.GetTensorMutableData<float>();
        
        // Find max score and label
        float max_score = -std::numeric_limits<float>::max();
        int max_idx = -1;
        
        for (size_t i = 0; i < output_tensor.GetTensorTypeAndShapeInfo().GetElementCount(); ++i) {
            if (output_data[i] > max_score) {
                max_score = output_data[i];
                max_idx = i;
            }
        }
        
        prediction.label = max_idx == 0 ? "SAFE" : "MALICIOUS";
        prediction.confidence = max_score;
        
        // Calculate scores for all classes
        std::vector<float> scores = output_tensor.GetTensorMutableData<float>();
        for (size_t i = 0; i < scores.size(); ++i) {
            prediction.scores[i == 0 ? "SAFE" : "MALICIOUS"] = scores[i];
        }
        
        return prediction;
        
    } catch (const Ort::Exception& e) {
        throw std::runtime_error("Inference error: " + std::string(e.what()));
    }
}

std::vector<float> MLInference::extractFeatures(const std::string& text) {
    std::vector<float> features;
    
    // Combine different feature types
    auto text_features = processTextFeatures(text);
    auto ngram_features = processNgramFeatures(text);
    auto statistical_features = processStatisticalFeatures(text);
    
    features.insert(features.end(), text_features.begin(), text_features.end());
    features.insert(features.end(), ngram_features.begin(), ngram_features.end());
    features.insert(features.end(), statistical_features.begin(), statistical_features.end());
    
    return features;
}

std::vector<float> MLInference::processTextFeatures(const std::string& text) {
    std::vector<float> features;
    
    // Text length
    features.push_back(static_cast<float>(text.length()));
    
    // Capital letters ratio
    int cap_count = std::count_if(text.begin(), text.end(), ::isupper);
    features.push_back(static_cast<float>(cap_count) / text.length());
    
    // Special characters ratio
    int special_count = std::count_if(text.begin(), text.end(), 
        [](char c) { return !isalnum(c) && !isspace(c); });
    features.push_back(static_cast<float>(special_count) / text.length());
    
    return features;
}

std::vector<float> MLInference::processNgramFeatures(const std::string& text) {
    std::vector<float> features;
    std::map<std::string, int> ngrams;
    
    // Count 2-grams
    for (size_t i = 0; i < text.length() - 1; ++i) {
        ngrams[text.substr(i, 2)]++;
    }
    
    // Calculate frequencies
    for (const auto& ngram : ngrams) {
        features.push_back(static_cast<float>(ngram.second) / text.length());
    }
    
    return features;
}

std::vector<float> MLInference::processStatisticalFeatures(const std::string& text) {
    std::vector<float> features;
    
    // Word count
    std::istringstream iss(text);
    int word_count = std::distance(std::istream_iterator<std::string>(iss),
                                  std::istream_iterator<std::string>());
    features.push_back(static_cast<float>(word_count));
    
    // Average word length
    float total_length = 0;
    for (const auto& word : text) {
        if (isalpha(word)) {
            total_length += 1;
        }
    }
    features.push_back(total_length / word_count);
    
    return features;
}
