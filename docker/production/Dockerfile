# Build stage for C++ module
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    make \
    g++ \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy C++ source files
COPY cpp/ ./cpp/

# Build C++ module
RUN mkdir -p cpp/build && \
    cd cpp/build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir -r requirements.txt

# Copy C++ module from builder
COPY --from=builder /build/cpp/build/libsecurity_analyzer.so /app/cpp/build/

# Copy only necessary application code
COPY app/ ./app/
COPY run.py .
COPY .env.example .env  # In production, use a proper secret management solution

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV CPP_MODULE_PATH=/app/cpp/build/libsecurity_analyzer.so

# Create non-root user
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose ports
EXPOSE 8000 8001

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/status || exit 1

# Run the application
CMD ["python", "run.py"]
