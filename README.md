# Hugging Face Security Gateway

A cloud-based security gateway service that acts as a secure proxy for Hugging Face models, providing input validation, content filtering, and security analysis before forwarding requests to Hugging Face APIs.

## Features

- Security Gateway: Validates and filters all inputs before processing
- Multi-format Support: Text, PDF, images, and other file formats
- High-performance C++ NLP Engine
- Cloud-Native: Containerized deployment with auto-scaling
- API Compatibility: Maintains Hugging Face API compatibility

## API Endpoints

### Health Check
```
GET /health
```

### Text Analysis
```
POST /api/v1/analyze/text
```
Request:
```json
{
  "text": "Input text to analyze",
  "model": "bert-base-uncased",
  "task": "sentiment-analysis",
  "security_level": "high"
}
```

### File Processing
```
POST /api/v1/analyze/file
```
Request:
```
multipart/form-data
file: <uploaded_file>
model: "document-qa"
task: "question-answering"
security_level: "medium"
```

### Hugging Face Proxy
```
POST /api/v1/models/{model_name}
```
Request:
```json
{
  "inputs": "validated input",
  "parameters": {...}
}
```

## Setup and Installation

### Prerequisites
- Python 3.11+
- Docker
- Redis
- PostgreSQL

### Installation
1. Clone the repository
2. Create a `.env` file with your configuration
3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running the Application

#### Local Development
```bash
uvicorn app.main:app --reload
```

#### Docker
```bash
docker build -t huggingface-secure-proxy .
docker run -p 8000:8000 huggingface-secure-proxy
```

## Configuration

The application uses environment variables for configuration. Create a `.env` file with the following variables:

```env
# Security Settings
SECURITY_THRESHOLD=0.8
MAX_REQUEST_SIZE=10485760

# Model Settings
DEFAULT_MODEL=distilbert-base-uncased

# Cache Settings
CACHE_TTL=3600
MAX_CACHE_SIZE=1000

# Database Settings
DB_HOST=localhost
DB_PORT=5432
DB_NAME=security_gateway
DB_USER=admin
DB_PASSWORD=

# Redis Settings
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

## Security Features

- Input validation and sanitization
- Content filtering
- PII detection
- Rate limiting
- Request size limits
- Security threshold configuration

## Monitoring

The application includes Prometheus metrics for monitoring:

- Request processing time
- Success/failure rates
- Model usage statistics
- Security validation metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License
