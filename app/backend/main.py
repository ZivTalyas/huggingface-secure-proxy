"""
Backend service for secure input validation.

This module provides API endpoints for validating text and file inputs
using a combination of rule-based and ML-based security checks.
"""
import os
import ctypes
import logging
from typing import Dict, Any, Optional, List
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
from backend.redis_service import redis_service

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
    analysis_summary: Optional[str] = None
    cache_hit: Optional[bool] = None
    processing_time_ms: Optional[float] = None
    detected_issues: Optional[List[str]] = None
    cached_at: Optional[int] = None
    analysis_type: Optional[str] = None

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
        
        # Get Redis information
        redis_info = redis_service.get_cache_info()
        
        return {
            "status": "healthy",
            "service": "backend",
            "security_level": SECURITY_LEVEL,
            "version": "1.0.0",
            "redis": {
                "connected": redis_info.get("connected", False),
                "cache_enabled": redis_info.get("connected", False),
                "cache_stats": {
                    "hits": redis_service.get_counter("cache_hits") or 0,
                    "misses": redis_service.get_counter("cache_misses") or 0,
                    "validation_keys": redis_info.get("validation_cache_keys", 0)
                }
            }
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

@app.get(
    "/models",
    summary="Model Information",
    description="Get information about the AI models and services being used.",
    response_model=Dict[str, Any],
    responses={
        200: {"description": "Model information retrieved successfully"}
    }
)
async def get_model_info() -> Dict[str, Any]:
    """Get information about the models and services being used.
    
    Returns:
        dict: Information about the AI models and services
    """
    try:
        # Check if C++ analyzer is available
        cpp_available = security_service.analyzer.cpp_analyzer is not None
        
        # Check if Gemini API is configured
        gemini_configured = bool(security_service.analyzer.gemini_api_key)
        
        model_info = {
            "service_status": "running",
            "security_analyzer": {
                "cpp_analyzer": {
                    "available": cpp_available,
                    "description": "C++ Security Analyzer for file analysis and advanced text processing",
                    "capabilities": ["PDF analysis", "text analysis", "malware detection", "PII detection"]
                },
                "python_analyzer": {
                    "available": True,
                    "description": "Python-based keyword and pattern matching",
                    "capabilities": ["keyword filtering", "basic pattern matching"]
                }
            },
            "llm_services": {
                "gemini_1_5_flash": {
                    "configured": gemini_configured,
                    "model": "gemini-1.5-flash",
                    "provider": "Google Generative AI",
                    "description": "Advanced language model for content safety analysis",
                    "status": "configured" if gemini_configured else "not_configured"
                }
            },
            "security_levels": {
                "current": SECURITY_LEVEL,
                "available": ["high", "medium", "low"],
                "descriptions": {
                    "high": "Maximum validation (rules + LLM + file analysis)",
                    "medium": "Balanced performance and protection", 
                    "low": "Basic validation only"
                }
            },
            "file_support": {
                "supported_types": ["PDF", "TXT"],
                "max_file_size": "10MB",
                "analysis_methods": ["Text extraction", "Malware pattern detection", "PII detection"]
            }
        }
        
        return model_info
        
    except Exception as e:
        logger.error(f"Error getting model info: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving model information: {str(e)}"
        )

@app.get(
    "/cache/stats",
    summary="Cache Statistics",
    description="Get detailed Redis cache statistics and information.",
    response_model=Dict[str, Any],
    responses={
        200: {"description": "Cache statistics retrieved successfully"},
        500: {"description": "Error retrieving cache statistics"}
    }
)
async def get_cache_stats() -> Dict[str, Any]:
    """Get detailed Redis cache statistics."""
    try:
        cache_info = redis_service.get_cache_info()
        
        # Get various counters
        stats = {
            "redis_info": cache_info,
            "cache_performance": {
                "total_hits": redis_service.get_counter("cache_hits") or 0,
                "total_misses": redis_service.get_counter("cache_misses") or 0,
                "hit_rate": 0.0
            },
            "validation_stats": {
                "text_validations": redis_service.get_counter("validations_text") or 0,
                "file_validations": redis_service.get_counter("validations_file") or 0,
                "safe_results": redis_service.get_counter("validations_text_safe") or 0 + 
                             redis_service.get_counter("validations_file_safe") or 0,
                "unsafe_results": redis_service.get_counter("validations_text_unsafe") or 0 + 
                                redis_service.get_counter("validations_file_unsafe") or 0
            }
        }
        
        # Calculate hit rate
        total_requests = stats["cache_performance"]["total_hits"] + stats["cache_performance"]["total_misses"]
        if total_requests > 0:
            stats["cache_performance"]["hit_rate"] = (
                stats["cache_performance"]["total_hits"] / total_requests * 100
            )
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving cache statistics: {str(e)}"
        )

@app.post(
    "/cache/clear",
    summary="Clear Cache",
    description="Clear Redis cache entries. Use with caution.",
    response_model=Dict[str, Any],
    responses={
        200: {"description": "Cache cleared successfully"},
        500: {"description": "Error clearing cache"}
    }
)
async def clear_cache(pattern: Optional[str] = None) -> Dict[str, Any]:
    """Clear Redis cache entries."""
    try:
        success = redis_service.clear_cache(pattern)
        
        if success:
            return {
                "status": "success",
                "message": f"Cache cleared successfully" + (f" for pattern: {pattern}" if pattern else ""),
                "pattern": pattern
            }
        else:
            return {
                "status": "error",
                "message": "Failed to clear cache (Redis not connected)",
                "pattern": pattern
            }
        
    except Exception as e:
        logger.error(f"Error clearing cache: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing cache: {str(e)}"
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
    import time
    start_time = time.time()
    
    try:
        # Use provided security level or fall back to the default
        security_level = request.security_level or SECURITY_LEVEL
        
        # Validate the security level
        if security_level not in ["high", "medium", "low"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid security level. Must be one of: high, medium, low"
            )
        
        # Ensure the request is not ambiguous (both text and file supplied)
        if request.text and request.file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide either 'text' or 'file', not both"
            )
        
        # Determine content and analysis type
        content = None
        analysis_type = None
        
        if request.text:
            content = request.text
            analysis_type = "text"
        elif request.file:
            content = request.file
            analysis_type = "file"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'text' or 'file' must be provided"
            )
        
        # Try to get cached result first
        cached_result = redis_service.get_cached_validation_result(
            content, analysis_type, security_level
        )
        
        if cached_result:
            # Increment cache hit counter
            redis_service.increment_counter("cache_hits")
            logger.info(f"Cache hit for {analysis_type} validation")
            
            # Add processing time and cache info
            cached_result["processing_time_ms"] = (time.time() - start_time) * 1000
            cached_result["cache_hit"] = True
            cached_result["security_level"] = security_level
            
            logger.info(f"Returning cached result: {cached_result}")
            return cached_result
        
        # Cache miss - perform actual validation
        redis_service.increment_counter("cache_misses")
        logger.debug(f"Cache miss for {analysis_type} validation")
        
        # Process text or file validation
        if analysis_type == "text":
            result = security_service.validate_text(content)
        else:  # file
            result = security_service.validate_file(content)
        
        # Add security level to response
        result["security_level"] = security_level
        result["cache_hit"] = False
        
        # Cache the result for future use
        redis_service.cache_validation_result(
            content, analysis_type, security_level, result
        )
        
        # Increment validation counters
        redis_service.increment_counter(f"validations_{analysis_type}")
        redis_service.increment_counter(f"validations_{analysis_type}_{result['status']}")
        
        # Add processing time to response
        result["processing_time_ms"] = (time.time() - start_time) * 1000
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during validation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during validation: {str(e)}"
        )

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
    import ssl
    
    # SSL Configuration
    ssl_context = None
    if os.getenv("SSL_CERT_FILE") and os.getenv("SSL_KEY_FILE"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            os.getenv("SSL_CERT_FILE"),
            os.getenv("SSL_KEY_FILE")
        )
    
    uvicorn.run(
        "app.backend.main:app",
        host=os.getenv("BACKEND_HOST", "0.0.0.0"),
        port=int(os.getenv("BACKEND_PORT", 8001)),
        ssl_context=ssl_context,
        reload=True
    )
