# Secure Input Proxy

[![Production is Live](https://img.shields.io/badge/Production-Live-brightgreen?logo=render&style=for-the-badge)](https://safe-input-proxy-frontend.onrender.com)

A secure input validation proxy designed to protect NLP/ML models and applications from malicious or harmful content. It analyzes text and file inputs using a combination of rule-based filtering, keyword detection, and performance-optimized C++ security analysis.

---
## 🎬 Demo

![Demo](demo/demo.gif)

### Key Features Demonstrated:
- **Real-time Text Validation**: Instant feedback on text input safety
- **File Upload Security**: Secure processing of PDF and TXT files
- **Configurable Security Levels**: High, Medium, Low protection modes
- **Detailed Analysis Results**: Comprehensive security scoring and issue detection
- **Redis Caching**: Lightning-fast responses with 95%+ performance improvement
- **Modern Web Interface**: Clean, responsive design for easy testing

---

## 🌐 [Try the Live Application!](https://safe-input-proxy-frontend.onrender.com)

[![Open in Production](https://img.shields.io/badge/Open%20App-Frontend-blue?logo=render&style=for-the-badge)](https://safe-input-proxy-frontend.onrender.com)

> ⏳ **Note**: The app may take up to 15 seconds to load initially due to free tier hosting cold starts.

---

## 🚦 CI/CD Status

| Workflow         | Status |
|------------------|--------|
| Docker Publish   | ![Docker Publish](https://github.com/zivtalyas/safe-input-proxy/actions/workflows/docker-publish.yml/badge.svg) |
| Test Cloud       | ![Test Cloud](https://github.com/zivtalyas/safe-input-proxy/actions/workflows/test-cloud.yml/badge.svg) |

---

## 🤔 Why This App?

In today's AI-driven world, protecting your applications from harmful, malicious, or inappropriate content is critical. This proxy acts as a security gateway that:

- **Prevents Injection Attacks**: Filters SQL injection, XSS, and other code injection attempts
- **Blocks Harmful Content**: Identifies toxic language, hate speech, and inappropriate material
- **Validates File Uploads**: Safely processes PDF and text files before they reach your models
- **Ensures Compliance**: Helps maintain content standards for user-facing AI applications
- **Protects Model Performance**: Prevents adversarial inputs that could compromise ML model behavior
- **Delivers Lightning-Fast Performance**: Redis caching provides 95%+ speed improvement for repeated validations

Perfect for chatbots, content moderation systems, document processing pipelines, and any application that processes user-generated content.

---

## 🚀 How to Use the App

### Web Interface

1. **Visit the Live App**: Go to [safe-input-proxy-frontend.onrender.com](https://safe-input-proxy-frontend.onrender.com)

2. **Choose Input Method**:
   - **Text Input**: Type or paste text directly into the textarea
   - **File Upload**: Click "Attach File" to upload PDF or TXT files

3. **Select Security Level**:
   - **High**: Maximum protection (rule-based + ML analysis + deep file inspection)
   - **Medium**: Balanced performance and security
   - **Low**: Basic rule-based validation only

4. **Validate**: Click the "Validate" button to analyze your input

5. **Review Results**: Get detailed feedback including:
   - Safety status (Safe/Unsafe/Error)
   - Confidence scores
   - Detected issues
   - Analysis summary

### API Usage

#### Validate Text
```bash
curl -X POST https://safe-input-proxy-frontend.onrender.com/validate-input \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Hello, this is a test message",
    "security_level": "high"
  }'
```

#### Validate File (Base64 encoded)
```bash
curl -X POST https://safe-input-proxy-frontend.onrender.com/validate-input \
  -H "Content-Type: application/json" \
  -d '{
    "file": "base64-encoded-file-content",
    "security_level": "high"
  }'
```

#### Response Format
```json
{
  "status": "safe",
  "reason": "safe",
  "llm_score": 0.85,
  "rule_score": 0.92,
  "overall_score": 0.88,
  "detected_issues": [],
  "analysis_summary": "Content passed all security checks",
  "processing_time_ms": 45.2,
  "cache_hit": true,
  "security_level": "high"
}
```

#### Redis Cache Management

**Get Cache Statistics**:
```bash
curl -X GET https://safe-input-proxy-frontend.onrender.com/cache/stats
```

**Clear Cache** (use with caution):
```bash
curl -X POST https://safe-input-proxy-frontend.onrender.com/cache/clear
```

**Cache Statistics Response**:
```json
{
  "redis_info": {
    "connected": true,
    "redis_version": "7.2.1",
    "used_memory": "2.5MB",
    "total_keys": 150
  },
  "cache_performance": {
    "total_hits": 324,
    "total_misses": 89,
    "hit_rate": 78.4
  },
  "validation_stats": {
    "text_validations": 200,
    "file_validations": 50,
    "safe_results": 180,
    "unsafe_results": 70
  }
}
```

### Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/zivtalyas/safe-input-proxy.git
   cd safe-input-proxy
   ```

2. **Quick start with Docker**:
   ```bash
   # Make setup script executable
   chmod +x setup.sh
   
   # Run automated setup
   ./setup.sh
   ```

3. **Manual Docker setup**:
   ```bash
   # Copy environment variables
   cp .env.example .env
   
   # Build and start services
   docker-compose -f docker/dev/docker-compose.yml up --build
   ```

4. **Access the application**:
   - Frontend: http://localhost:8000
   - Backend API: http://localhost:8001
   - Redis: localhost:6379

5. **Test Redis caching performance**:
   ```bash
   # Run the performance demo
   python test/redis_test.py
   ```

6. **Monitor cache performance**:
   ```bash
   # Check cache statistics
   curl http://localhost:8001/cache/stats
   
   # Check health with Redis status
   curl http://localhost:8001/health
   ```

### HTTPS Support

The application supports HTTPS for enhanced security:

1. **Generate SSL certificates**:
   ```bash
   python run.py generate-certs
   ```

2. **Start with HTTPS**:
   ```bash
   python run.py start --generate-certs
   ```

3. **Access via HTTPS**:
   - Frontend: https://localhost:8443 (HTTPS)
   - Backend API: https://localhost:8444 (HTTPS)
   - HTTP fallback still available

📖 **Full HTTPS Setup Guide**: See [HTTPS-SETUP.md](HTTPS-SETUP.md) for comprehensive configuration instructions.

---

## 🚀 Performance & Redis Caching

### Performance Benchmarks

Redis caching provides dramatic performance improvements:

| Operation | Without Cache | With Cache Hit | Improvement |
|-----------|---------------|----------------|-------------|
| Text Validation | 200-500ms | 5-15ms | **95%+ faster** |
| File Validation | 1-3 seconds | 10-20ms | **98%+ faster** |
| API Response | 300-800ms | 15-30ms | **90%+ faster** |

### Caching Strategy

- **Smart TTL Management**: Different cache durations for different content types
  - Text validations: 30 minutes
  - File validations: 2 hours
- **SHA-256 Hashing**: Unique cache keys prevent collisions
- **Graceful Degradation**: System works normally even if Redis is unavailable
- **Automatic Cleanup**: Cache entries expire automatically to prevent memory bloat

### Real-World Performance Demo

```bash
# Run the performance demo to see Redis benefits
python test/redis_test.py

# Expected output:
# 🚀 Redis Caching Performance Demo
# =====================================
# 
# Average request time: 45.2ms
# Cache hit rate: 66.7%
# Speed improvement: 92.1%
```

### Benefits for Production

- **Cost Savings**: Reduces expensive AI API calls by caching results
- **Better User Experience**: Near-instant responses for cached content
- **Higher Throughput**: Handle more concurrent requests with same resources
- **Lower Latency**: Millisecond responses vs. seconds for complex validations

### Redis Configuration

The application uses environment variables for Redis configuration:

```bash
# Redis Connection
REDIS_HOST=redis           # Redis server hostname
REDIS_PORT=6379           # Redis server port

# Cache TTL Settings (in seconds)
REDIS_DEFAULT_TTL=3600    # Default cache TTL (1 hour)
REDIS_TEXT_CACHE_TTL=1800 # Text validation cache TTL (30 minutes)
REDIS_FILE_CACHE_TTL=7200 # File validation cache TTL (2 hours)
```

Redis is automatically configured in both development and production Docker environments with optimal settings for performance and reliability.

---

## ⚡ Technical Choices & Architecture

### Framework & Language Stack
- **FastAPI**: Modern Python web framework for both frontend and backend APIs
  - Automatic API documentation with OpenAPI/Swagger
  - High performance with async/await support
  - Built-in data validation with Pydantic models
  - Excellent for microservices architecture

- **Python 3.8+**: Primary development language
  - Rich ecosystem for security and ML libraries
  - Easy integration with C++ modules
  - Strong community support

### Performance & Core Processing
- **C++ Security Analyzer**: Performance-critical security analysis
  - Custom-built security analyzer in C++ for speed
  - Python bindings for seamless integration
  - Handles intensive text processing and pattern matching
  - PDF processing capabilities with Poppler library

### Architecture Pattern
- **Microservices Architecture**: Separated concerns for scalability
  - **Frontend Service** (Port 8000): HTTP API, static file serving, request routing
  - **Backend Service** (Port 8001): Heavy security analysis, ML processing, cache management
  - **Redis Service** (Port 6379): High-performance caching, statistics, future rate limiting
  
- **Benefits**:
  - Crash isolation (frontend stays up if backend fails)
  - Independent scaling of services
  - Dramatic performance improvements (95%+ faster responses)
  - Easier maintenance and deployment
  - Cost reduction through intelligent caching

### Containerization & Deployment
- **Docker & Docker Compose**: Complete containerization
  - Multi-service orchestration
  - Development and production configurations
  - Consistent environments across deployments
  - Easy scaling and load balancing

- **Render Platform**: Production hosting
  - Free tier deployment
  - Automatic deployments from GitHub
  - Built-in SSL and CDN
  - Container registry integration (GHCR)

### CI/CD Pipeline
- **GitHub Actions**: Automated workflows
  - Docker image building and publishing
  - Automated testing on cloud infrastructure
  - Container registry management
  - Deploy on commit triggers

### Security Implementation
- **Multi-layered Security Approach**:
  - **Rule-based Filtering**: Harmful keywords detection (100+ patterns)
  - **Pattern Matching**: SQL injection, XSS, code injection detection
  - **File Analysis**: Safe PDF and text file processing
  - **Configurable Thresholds**: Adjustable security levels

- **Security Features**:
  - Input sanitization and validation
  - File type verification
  - Size limits (10MB max)
  - Base64 encoding for safe file transfer
  - Temporary file handling with cleanup

### Data & Caching
- **Redis**: In-memory data structure store for high-performance caching
  - **Validation Result Caching**: Stores analysis results with smart TTL management
  - **Performance Monitoring**: Real-time cache hit/miss statistics and performance metrics
  - **Hash-based Keys**: SHA-256 content hashing ensures unique, collision-free cache keys
  - **Configurable TTL**: Different cache durations for text (30min) vs files (2hr)
  - **Graceful Degradation**: System continues operation even if Redis is unavailable
  - **Memory Management**: Automatic cleanup with LRU eviction policy (256MB limit)
  - **Production Ready**: Persistent storage with AOF, health checks, and monitoring
  - **Future Extensions**: Ready for rate limiting, session management, and pub/sub

### Development Tools
- **Environment Management**: `.env` files for configuration
- **Health Checks**: Built-in service monitoring
- **Logging**: Comprehensive logging across services
- **Hot Reloading**: Development-friendly auto-restart

### Why These Choices?

1. **FastAPI**: Chosen for its modern async capabilities, automatic documentation, and excellent performance
2. **Microservices**: Allows independent scaling and better fault tolerance
3. **C++**: Critical for performance in security analysis - significantly faster than pure Python
4. **Docker**: Ensures consistent deployment across environments and simplifies scaling
5. **Redis**: Essential for production performance - 95%+ speed improvement, cost savings, and scalability
6. **Render**: Free, reliable hosting with good CI/CD integration for open source projects

This architecture provides a robust, scalable, and maintainable solution for secure input validation while maintaining excellent performance and developer experience.

---

## 📊 Service Health

Check all services status (including Redis):
```bash
./healthcheck.sh
```

The health check now includes Redis connectivity status and cache performance metrics. You can also check individual service health:

```bash
# Backend health with Redis status
curl http://localhost:8001/health

# Cache statistics
curl http://localhost:8001/cache/stats
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
