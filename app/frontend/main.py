from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional, Union
import httpx
import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

app = FastAPI(title="Secure Input Validation Proxy - Frontend")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL")
if not BACKEND_URL:
    BACKEND_HOST = os.getenv("BACKEND_HOST", "localhost")
    BACKEND_PORT = os.getenv("BACKEND_PORT", "8001")
    BACKEND_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}"
TIMEOUT = 30.0  # seconds

# Determine static directory path relative to this file
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class ValidationRequest(BaseModel):
    text: Optional[str] = None
    file: Optional[str] = None  # base64 encoded file content
    security_level: str = "high"

@app.get("/")
async def index():
    """Serve the main application page."""
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/get-backend-url")
async def get_backend_url():
    """Expose the backend URL to the client-side script."""
    return {"url": BACKEND_URL}

@app.get("/status")
async def get_status():
    """Check if the application and its internal systems are running."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BACKEND_URL}/health", timeout=5.0)
            backend_status = response.status_code == 200
            
        return {
            "status": "available" if backend_status else "degraded",
            "backend_status": "healthy" if backend_status else "unavailable"
        }
    except Exception as e:
        return {
            "status": "degraded",
            "backend_status": "unavailable",
            "error": str(e)
        }

@app.get("/models")
async def get_models():
    """Get information about the AI models being used."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BACKEND_URL}/models",
                timeout=TIMEOUT
            )
            
            if response.status_code != 200:
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"status": "error", "reason": "Backend model info failed"}
                )
                
            return response.json()
            
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"status": "error", "reason": "Backend request timed out"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "reason": str(e)}
        )

@app.post("/validate-input")
async def validate_input(request: ValidationRequest):
    """
    Validate an input (text or file) before it reaches a chatbot or NLP model.
    
    Security levels:
    - high: Maximum validation (rules + LLM + file analysis)
    - medium: Balanced performance and protection
    - low: Basic validation only
    """
    if not request.text and not request.file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'text' or 'file' must be provided"
        )
    
    if request.security_level not in ["high", "medium", "low"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="security_level must be one of: high, medium, low"
        )
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BACKEND_URL}/validate",
                json=request.dict(),
                timeout=TIMEOUT
            )
            
            if response.status_code != 200:
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"status": "error", "reason": "Backend validation failed"}
                )
                
            return response.json()
            
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"status": "error", "reason": "Backend validation timed out"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "reason": str(e)}
        )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "reason": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.frontend.main:app",
        host=os.getenv("FRONTEND_HOST", "0.0.0.0"),
        port=int(os.getenv("FRONTEND_PORT", 8000)),
        reload=True
    )
