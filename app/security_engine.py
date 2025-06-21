import asyncio
import json
import os
import logging
from typing import Dict, Any, Optional, List, Union
import numpy as np

from transformers import pipeline
import torch

# Initialize logger
logger = logging.getLogger(__name__)

# Global flag for C++ module availability
CPP_AVAILABLE = False
try:
    import security_cpp
    CPP_AVAILABLE = True
except ImportError:
    security_cpp = None
    logger.warning("C++ security modules not available. Running in Python-only mode.")

class SecurityEngine:
    def __init__(self):
        # Initialize C++ components if available
        self.analyzer = None
        self.processor = None
        self.cpp_available = CPP_AVAILABLE
        
        if self.cpp_available:
            try:
                self.analyzer = security_cpp.SecurityAnalyzer()
                self.processor = security_cpp.TextProcessor()
            except Exception as e:
                logger.error(f"Failed to initialize C++ components: {e}")
                self.cpp_available = False
        
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
        if self.analyzer and self.processor:
            try:
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
            except Exception as e:
                logger.error(f"Error in C++ text validation: {e}")
        
        # Fallback to ML-only validation if C++ is not available or fails
        try:
            ml_result = self.security_model(text)[0]
            is_safe = ml_result["label"] == "POSITIVE" and ml_result["score"] >= 0.8
            return {
                "is_safe": is_safe,
                "confidence": ml_result["score"],
                "issues": [],
                "analysis_summary": "ML-based validation only"
            }
        except Exception as e:
            logger.error(f"Error in ML text validation: {e}")
            # Default to safe if all validations fail
            return {
                "is_safe": True,
                "confidence": 1.0,
                "issues": [],
                "analysis_summary": "Validation failed, defaulting to safe"
            }

    async def validate_file(self, file_data: bytes) -> Dict[str, Any]:
        """Validate file content for security concerns."""
        if self.analyzer and self.processor:
            try:
                # Use C++ implementation for file validation if available
                result = self.analyzer.analyzePDF(file_data)
                
                # If file is safe, extract text for additional analysis
                if result.is_safe:
                    text_content = self.processor.extractTextFromPDF(file_data)
                    text_result = await self.validate_text(text_content)
                    result.confidence_score = min(result.confidence_score, text_result["confidence"])
                    result.is_safe = result.confidence_score >= 0.8
                    result.detected_issues.extend(text_result.get("issues", []))
                
                return {
                    "is_safe": result.is_safe,
                    "confidence": result.confidence_score,
                    "issues": result.detected_issues,
                    "analysis_summary": result.analysis_summary
                }
            except Exception as e:
                logger.error(f"Error in C++ file validation: {e}")
        
        # Fallback to basic validation if C++ is not available or fails
        try:
            # Simple check for common malicious file signatures
            is_safe = True
            issues = []
            
            # Check for common executable file headers
            if file_data.startswith((b'MZ', b'\x7fELF', b'#!', b'%PDF')):
                is_safe = False
                issues.append("Potentially executable file detected")
            
            return {
                "is_safe": is_safe,
                "confidence": 0.5,  # Lower confidence for basic validation
                "issues": issues,
                "analysis_summary": "Basic file validation only (C++ components not available)"
            }
        except Exception as e:
            logger.error(f"Error in basic file validation: {e}")
            # Default to safe if all validations fail
            return {
                "is_safe": True,
                "confidence": 1.0,
                "issues": [],
                "analysis_summary": "File validation failed, defaulting to safe"
            }

    async def validate_input(self, input_data: str) -> Dict[str, Any]:
        """Validate generic input data."""
        try:
            # Clean and tokenize input if processor is available
            if self.processor:
                try:
                    cleaned_text = self.processor.cleanText(input_data)
                    tokens = self.processor.tokenize(cleaned_text)
                except Exception as e:
                    logger.warning(f"Error in input preprocessing: {e}")
                    cleaned_text = input_data
                    tokens = []
            else:
                cleaned_text = input_data
                tokens = []
            
            # Run security analysis
            validation_result = await self.validate_text(cleaned_text)
            
            # Ensure we have consistent return values
            return {
                "is_safe": validation_result.get("is_safe", True),
                "confidence": validation_result.get("confidence", 1.0),
                "issues": validation_result.get("issues", []),
                "analysis_summary": validation_result.get("analysis_summary", "Input validation completed")
            }
            
        except Exception as e:
            logger.error(f"Error in input validation: {e}")
            # Default to safe if validation fails
            return {
                "is_safe": True,
                "confidence": 0.5,
                "issues": [f"Validation error: {str(e)}"],
                "analysis_summary": "Input validation failed, defaulting to safe"
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
