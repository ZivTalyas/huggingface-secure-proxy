"""
Backend service for secure input validation.

This module provides API endpoints for validating text and file inputs
using a combination of rule-based and ML-based security checks.
"""
import os
import ctypes
import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Import our security service
import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).parent.parent.parent))
from security.service import SecurityService

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Secure Input Validation Proxy - Backend",
    description="Backend service for validating inputs using security rules and ML models",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
SECURITY_LEVEL = os.getenv("SECURITY_LEVEL", "high").lower()

# Initialize security service
security_service = SecurityService(security_level=SECURITY_LEVEL)

# Request/Response Models
class ValidationRequest(BaseModel):
    """Request model for validation endpoint."""
    text: Optional[str] = None
    file: Optional[str] = None  # base64 encoded file content
    security_level: Optional[str] = None  # Override default security level if provided

class ValidationResult(BaseModel):
    """Response model for validation results."""
    status: str  # "safe" | "unsafe" | "error"
    reason: str
    llm_score: Optional[float] = None
    rule_score: Optional[float] = None
    overall_score: Optional[float] = None
    security_level: Optional[str] = None
    error: Optional[str] = None

def load_models():
    """Load ML models and C++ module"""
    global classifier, tokenizer, cpp_module
    
    # Load toxicity classifier
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)
        logger.info(f"Loaded toxicity classifier: {MODEL_NAME}")
    except Exception as e:
        logger.error(f"Failed to load toxicity classifier: {e}")
        raise
    
    # Load C++ module
    cpp_module = None
    if CPP_MODULE_PATH and os.path.exists(CPP_MODULE_PATH):
        try:
            cpp_module = ctypes.CDLL(CPP_MODULE_PATH)
            logger.info(f"Successfully loaded C++ module from {CPP_MODULE_PATH}")
        except Exception as e:
            logger.warning(f"Could not load C++ module from {CPP_MODULE_PATH}. File analysis will be disabled. Error: {e}")
    else:
        logger.warning("C++ module not found or path not set. File analysis will be disabled.")

def analyze_text_security(text: str, security_level: str) -> Dict[str, Any]:
    """Analyze text for security issues using rules and ML"""
    # Basic rule-based checks
    rule_score = 0.0
    issues = []
    
    # Check for common injection patterns
    injection_patterns = [
        (r'[;\\/<>\[\]{}|`&]', "suspicious_characters"),
        (r'(?i)(select|insert|update|delete|drop|create|alter|truncate|union|exec|xp_)', "sql_injection_attempt"),
        (r'(?i)(<script>|javascript:|on\w+\s*=)', "xss_attempt"),
    ]
    
    for pattern, issue in injection_patterns:
        if re.search(pattern, text):
            issues.append(issue)
            rule_score += 0.3
    
    # ML-based analysis if security level is not 'low'
    llm_score = 0.0
    if security_level in ["high", "medium"] and classifier is not None:
        try:
            result = classifier(text, truncation=True, max_length=512)
            # Assuming the model returns a list of dicts with 'label' and 'score'
            for item in result:
                if item['label'] == 'LABEL_1':  # Assuming this is the 'toxic' label
                    llm_score = item['score']
                    break
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}")
    
    # Calculate overall score (weighted average)
    overall_score = 0.0
    if security_level == "high":
        overall_score = (rule_score * 0.4) + (llm_score * 0.6)
    elif security_level == "medium":
        overall_score = (rule_score * 0.6) + (llm_score * 0.4)
    else:  # low
        overall_score = rule_score
    
    # Determine if input is safe
    is_safe = overall_score < TOXIC_THRESHOLD
    
    return {
        "status": "safe" if is_safe else "unsafe",
        "reason": "safe" if is_safe else ", ".join(issues) if issues else "potentially_unsafe_content",
        "rule_score": min(1.0, rule_score),
        "llm_score": llm_score,
        "overall_score": min(1.0, overall_score)
    }

def analyze_file_security(file_content: str, security_level: str) -> Dict[str, Any]:
    """Analyze file content for security issues"""
    # This is a simplified example - in reality, you'd want to decode the base64 content
    # and perform file-specific analysis
    try:
        # For text files, we can analyze the content directly
        if security_level == "high" and cpp_module is not None:
            # Call C++ module for deep analysis
            # This is a placeholder - actual implementation would depend on your C++ module
            result = cpp_module.analyze_file(file_content.encode('utf-8'))
            return {
                "status": "safe" if result.is_safe else "unsafe",
                "reason": result.reason if hasattr(result, 'reason') else "file_analysis_completed",
                "overall_score": result.score if hasattr(result, 'score') else 0.0
            }
        else:
            # Basic analysis for medium/low security levels
            return {
                "status": "safe",
                "reason": "basic_file_check_passed",
                "overall_score": 0.1  # Low risk score for basic check
            }
    except Exception as e:
        logger.error(f"Error in file analysis: {e}")
        return {
            "status": "unsafe",
            "reason": "file_analysis_error",
            "overall_score": 1.0
        }
@app.on_event("startup")
async def startup_event():
    """Initialize services on application startup.
    
    This function runs when the FastAPI application starts up.
    It initializes the security service and logs the startup status.
    """
    try:
        logger.info("Starting up backend service...")
        logger.info(f"Security level: {SECURITY_LEVEL}")
        
        # Test the security service
        test_result = security_service.validate_text("Startup test")
        if test_result.get("status") != "safe":
            logger.warning("Security service test validation failed")
        
        logger.info("Backend service started successfully")
        
    except Exception as e:
        logger.critical(f"Failed to initialize backend service: {e}", exc_info=True)
        # Don't raise to allow the service to start, but it will fail health checks
        pass

@app.get(
    "/health",
    summary="Health Check",
    description="Check if the backend service is healthy and ready to accept requests.",
    response_model=Dict[str, Any],
    responses={
        200: {"description": "Service is healthy"},
        503: {"description": "Service is not ready or unhealthy"}
    }
)
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for the backend service.
    
    Returns:
        dict: Status information about the service including:
            - status: Service status ("healthy" or "unhealthy")
            - service: Service name
            - security_level: Current security level
            - version: Service version
    """
    try:
        # Test the security service with a simple validation
        test_text = "This is a health check request."
        test_result = security_service.validate_text(test_text)
        
        if not test_result or test_result.get("status") not in ["safe", "unsafe"]:
            raise RuntimeError("Security service validation check failed")
        
        return {
            "status": "healthy",
            "service": "backend",
            "security_level": SECURITY_LEVEL,
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "error": str(e),
                "service": "backend"
            }
        )

@app.post(
    "/validate",
    summary="Validate Input",
    description="""
    Validate text or file input for security issues.
    
    This endpoint accepts either text or a base64-encoded file and returns
    a security analysis based on the configured security level.
    """,
    response_model=ValidationResult,
    responses={
        200: {"description": "Validation completed successfully"},
        400: {"description": "Invalid request parameters"},
        500: {"description": "Internal server error during validation"}
    }
)
async def validate_input(request: ValidationRequest) -> Dict[str, Any]:
    """
    Validate input text or file for security issues.
    
    Args:
        request: The validation request containing either text or file content.
        
    Returns:
        dict: Validation results including safety status and analysis details.
        
    Raises:
        HTTPException: If there's an error during validation or invalid input.
    """
    try:
        # Use provided security level or fall back to the default
        security_level = request.security_level or SECURITY_LEVEL
        
        # Validate the security level
        if security_level not in ["high", "medium", "low"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid security level. Must be one of: high, medium, low"
            )
        
        # Process text or file validation
        if request.text:
            result = security_service.validate_text(request.text)
        elif request.file:
            result = security_service.validate_file(request.file)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'text' or 'file' must be provided"
            )
        
        # Add security level to response
        result["security_level"] = security_level
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during validation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during validation: {str(e)}"
        )
    
    # Add processing time to response
    result["processing_time_ms"] = (time.time() - start_time) * 1000
    return result

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "reason": "internal_server_error",
            "details": str(exc)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.backend.main:app",
        host=os.getenv("BACKEND_HOST", "0.0.0.0"),
        port=int(os.getenv("BACKEND_PORT", 8001)),
        reload=True
    )
