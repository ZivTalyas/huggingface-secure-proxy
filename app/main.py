from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
from pydantic import BaseModel
import uvicorn
import logging
from datetime import datetime

from security_engine import SecurityEngine
from config import settings

app = FastAPI(title="Hugging Face Security Gateway", version="1.0.0")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize security engine
security_engine = SecurityEngine()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextAnalysisRequest(BaseModel):
    text: str
    model: str = "bert-base-uncased"
    task: str = "sentiment-analysis"
    security_level: str = "high"

class FileAnalysisRequest(BaseModel):
    model: str
    task: str
    security_level: str

class ModelRequest(BaseModel):
    inputs: str
    parameters: Dict[str, Any]

@app.get("/health")
async def health_check():
    return JSONResponse(content={
        "status": "healthy",
        "version": "1.0.0"
    })

@app.post("/api/v1/analyze/text")
async def analyze_text(request: TextAnalysisRequest):
    try:
        # Validate text security
        security_result = await security_engine.validate_text(request.text)
        
        if not security_result["is_safe"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Security validation failed",
                    "issues": security_result["issues"]
                }
            )
        
        # Process with Hugging Face model
        model_response = await security_engine.process_text(
            request.text,
            request.model,
            request.task
        )
        
        return {
            "success": True,
            "data": {
                "security_check": security_result,
                "model_response": model_response
            },
            "metadata": {
                "processing_time": 0.0,  # TODO: Implement timing
                "model_used": request.model,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing text: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    model: str = "document-qa",
    task: str = "question-answering",
    security_level: str = "medium"
):
    try:
        file_content = await file.read()
        
        # Validate file security
        security_result = await security_engine.validate_file(file_content)
        
        if not security_result["is_safe"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Security validation failed",
                    "issues": security_result["issues"]
                }
            )
        
        # Process file with appropriate model
        model_response = await security_engine.process_file(
            file_content,
            model,
            task
        )
        
        return {
            "success": True,
            "data": {
                "security_check": security_result,
                "model_response": model_response
            },
            "metadata": {
                "processing_time": 0.0,  # TODO: Implement timing
                "model_used": model,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/models/{model_name}")
async def process_model_request(
    model_name: str,
    request: ModelRequest
):
    try:
        # Validate input security
        security_result = await security_engine.validate_input(request.inputs)
        
        if not security_result["is_safe"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Security validation failed",
                    "issues": security_result["issues"]
                }
            )
        
        # Process with Hugging Face model
        model_response = await security_engine.process_model(
            model_name,
            request.inputs,
            request.parameters
        )
        
        return {
            "success": True,
            "data": {
                "security_check": security_result,
                "model_response": model_response
            },
            "metadata": {
                "processing_time": 0.0,  # TODO: Implement timing
                "model_used": model_name,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing model request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
