# Secure Input Validation Proxy

A secure input validation proxy designed to sit between users/chatbots and NLP/ML models. It ensures that only validated, safe text or file inputs are allowed to proceed into processing, protecting your system from malicious or harmful content.

## 🚀 Features

### Security Features

- **Input Validation**
  - Rule-based validation
  - ML-based content analysis
  - File content inspection (PDF, TXT)
  - Configurable security levels (high/medium/low)

- **Architecture**
  - Microservices design
  - Frontend/Backend separation
  - Crash isolation
  - Graceful degradation

### Development & Operations

- **Containerized**
  - Docker support out of the box
  - Development and production configurations
  - Easy scaling
  - Built-in health checks
  - Monitoring with Prometheus & Grafana

- **Developer Friendly**
  - Simple REST API
  - Comprehensive documentation
  - One-line setup script
  - Automated health checks
  - Built-in management script (`run.py`)

### Performance

- **Optimized**
  - C++ core for performance-critical operations
  - Redis caching layer
  - Asynchronous processing

## 🏗 Architecture

The system is designed with a microservices architecture using Docker containers:

### Services

1. **Frontend API** (`app/frontend/`)
   - Handles HTTP requests and API endpoints
   - Provides resilience against backend failures
   - Runs on port 8000

2. **Backend Service** (`app/backend/`)
   - Performs intensive validation and processing
   - Runs ML models and security checks
   - Handles file processing
   - Runs on port 8001

3. **Redis**
   - Used for caching and rate limiting
   - Runs on port 6379

### Directory Structure

```
.
├── app/                    # Application code
│   ├── backend/            # Backend service
│   ├── frontend/           # Frontend API
│   └── security/           # Security module with C++ bindings
├── cpp/                    # C++ security analyzer
│   ├── bindings/           # Python bindings for C++
│   ├── mlInterface/        # ML interface code
│   └── securityAnalyzer/    # Core security analysis
├── docker/                 # Docker configuration
│   ├── dev/                # Development Docker setup
│   └── production/         # Production Docker setup
├── tests/                  # Test files
├── .env.example           # Example environment variables
├── docker-compose.yml      # Main Docker Compose file
└── run.py                 # Management script
```

## 🚀 Getting Started

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- (For development) Python 3.8+, CMake, and build tools

### Quick Start with Docker

#### Option 1: Using the setup script (recommended)

1. Make the setup script executable:
   ```bash
   chmod +x setup.sh
   ```

2. Run the setup script:
   ```bash
   ./setup.sh
   ```

   This will:
   - Create a `.env` file from the example if it doesn't exist
   - Check for Docker and Docker Compose
   - Build and start all services
   - Provide you with the service URLs

#### Option 2: Manual setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-input-proxy.git
   cd secure-input-proxy
   ```

2. Copy the example environment file and configure it:
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

3. Build and start the services:
   ```bash
   # Build and start all services in detached mode
   ./run.py start --build
   
   # Or build and start in one command
   docker-compose -f docker/docker-compose.yml up --build -d
   ```

4. Access the services:
   - Frontend API: http://localhost:8000
   - Backend API: http://localhost:8001
   - Redis: localhost:6379

### Development Setup

The `run.py` script provides a convenient way to manage the application:

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Build the C++ module:
   ```bash
   mkdir -p cpp/build
   cd cpp/build
   cmake ..

### Running the Application

Start both frontend and backend servers:

```bash
python run.py
```

Or start them separately:

```bash
# In separate terminals
uvicorn app.frontend.main:app --reload --port 8000
uvicorn app.backend.main:app --reload --port 8001
```

## 🛠 Management Script

The `run.py` script provides a convenient way to manage the application:

```bash
# Start all services (in background)
./run.py start

# Build and start services
./run.py start --build

# Stop all services
./run.py stop

# Restart services
./run.py restart

# View logs (all services or specific service)
./run.py logs
./run.py logs frontend

# Build services without starting
./run.py build
```

## ✅ Health Checks

Check the status of all services with the health check script:

```bash
./healthcheck.sh
```

Example output:
```
🔍 Running health checks...

Checking Docker... ✓ RUNNING
Checking Docker Compose... ✓ RUNNING
Checking Redis... ✓ RUNNING
Checking Backend API... ✓ RUNNING
Checking Frontend API... ✓ RUNNING

📊 Service Status:
Frontend API: http://localhost:8000/status
Backend API:  http://localhost:8001/health
Redis:        localhost:6379
Prometheus:   http://localhost:9090
Grafana:      http://localhost:3000

✅ Health check completed!
```

## 📚 API Documentation

### Frontend API (Port 8000)

```http
POST /validate-input
Content-Type: application/json

{
  "text": "example user input",  // Optional (one of text or file is required)
  "file": "base64-encoded-content", // Optional
  "security_level": "high" | "medium" | "low"
}
```

**Example Response:**

```json
{
  "status": "safe",
  "reason": "safe",
  "llm_score": 0.12,
  "rule_score": 0.15,
  "overall_score": 0.13,
  "processing_time_ms": 42.5
}
```

### Check Status

```http
GET /status
```

**Example Response:**

```json
{
  "status": "available",
  "backend_status": "healthy"
}
```

## 🛡 Security Levels

| Level  | Description |
|--------|-------------|
| high   | Maximum validation (rules + LLM + file analysis) |
| medium | Balanced performance and protection |
| low    | Basic validation only |

## 🐳 Docker Deployment

Build and run with Docker Compose:

```bash
docker-compose up --build
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
