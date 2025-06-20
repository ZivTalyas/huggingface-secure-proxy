import asyncio
import json
import os
from typing import Dict, Any, Optional
import numpy as np

from transformers import pipeline
import torch
import security_cpp

class SecurityEngine:
    def __init__(self):
        # Initialize C++ components
        self.analyzer = security_cpp.SecurityAnalyzer()
        self.processor = security_cpp.TextProcessor()
        
        # Initialize ML models
        self.security_model = pipeline(
            "text-classification",
            model="distilbert-base-uncased-finetuned-sst-2-english",
            device=-1 if not torch.cuda.is_available() else 0
        )
        
        # Initialize NLP models
        self.nlp_models = {
            "sentiment-analysis": pipeline("sentiment-analysis"),
            "question-answering": pipeline("question-answering"),
            "document-qa": pipeline("document-question-answering")
        }

    async def validate_text(self, text: str) -> Dict[str, Any]:
        """Validate text content for security concerns."""
        result = self.analyzer.analyzeText(text)
        
        # Additional security checks using Python ML models
        if not result.is_safe:
            # Use ML model for secondary validation
            ml_result = self.security_model(text)[0]
            if ml_result["label"] == "POSITIVE":
                result.confidence_score = max(result.confidence_score, ml_result["score"])
                result.is_safe = result.confidence_score >= 0.8
        
        return {
            "is_safe": result.is_safe,
            "confidence": result.confidence_score,
            "issues": result.detected_issues,
            "analysis_summary": result.analysis_summary
        }

    async def validate_file(self, file_data: bytes) -> Dict[str, Any]:
        """Validate file content for security concerns."""
        # Use C++ implementation for file validation
        result = self.analyzer.analyzePDF(file_data)
        
        # If file is safe, extract text for additional analysis
        if result.is_safe:
            text_content = self.processor.extractTextFromPDF(file_data)
            text_result = self.validate_text(text_content)
            result.confidence_score = min(result.confidence_score, text_result["confidence"])
            result.is_safe = result.confidence_score >= 0.8
            result.detected_issues.extend(text_result["issues"])
        
        return {
            "is_safe": result.is_safe,
            "confidence": result.confidence_score,
            "issues": result.detected_issues,
            "analysis_summary": result.analysis_summary
        }

    async def validate_input(self, input_data: str) -> Dict[str, Any]:
        """Validate generic input data."""
        # Clean and tokenize input
        cleaned_text = self.processor.cleanText(input_data)
        tokens = self.processor.tokenize(cleaned_text)
        
        # Run security analysis
        result = self.analyzer.analyzeText(cleaned_text)
        
        return {
            "is_safe": result.is_safe,
            "confidence": result.confidence_score,
            "issues": result.detected_issues
        }

    async def process_text(self, text: str, model: str, task: str) -> Dict[str, Any]:
        """Process text through Hugging Face model."""
        if task not in self.nlp_models:
            raise ValueError(f"Unsupported task: {task}")
        
        model_pipeline = self.nlp_models[task]
        result = model_pipeline(text)
        
        return {
            "predictions": result,
            "confidence": max([pred["score"] for pred in result])
        }

    async def process_file(self, file_data: bytes, model: str, task: str) -> Dict[str, Any]:
        """Process file content through appropriate model."""
        text_content = self.processor.extractTextFromPDF(file_data)
        return await self.process_text(text_content, model, task)

    async def process_model(self, model_name: str, inputs: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Process request through specified Hugging Face model."""
        try:
            # Load model if not already loaded
            if model_name not in self.nlp_models:
                self.nlp_models[model_name] = pipeline(model=model_name)
            
            model_pipeline = self.nlp_models[model_name]
            result = model_pipeline(inputs, **parameters)
            
            return {
                "predictions": result,
                "confidence": max([pred["score"] for pred in result])
            }
        except Exception as e:
            raise ValueError(f"Error processing model request: {str(e)}")
