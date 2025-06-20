#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <onnxruntime/core/session/onnxruntime_cxx_api.h>
#include <nlohmann/json.hpp>

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
    std::unique_ptr<Ort::Session> session;
    Ort::Env env;
    Ort::SessionOptions session_options;
    
    std::vector<float> processTextFeatures(const std::string& text);
    std::vector<float> processNgramFeatures(const std::string& text);
    std::vector<float> processStatisticalFeatures(const std::string& text);
};
