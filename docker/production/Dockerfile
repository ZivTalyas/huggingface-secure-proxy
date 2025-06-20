# Stage 1: Build dependencies
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libssl-dev \
    libicu-dev \
    libboost-dev \
    libpoppler-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Build C++ components
WORKDIR /app/cpp
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make

# Stage 2: Production image
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libicu-dev \
    libpoppler-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy from builder
COPY --from=builder /usr/local/lib/python3.11/dist-packages /usr/local/lib/python3.11/dist-packages
COPY --from=builder /app/app /app/app
COPY --from=builder /app/cpp/build /app/cpp/build
COPY --from=builder /app/requirements.txt .

# Set up environment variables
ENV PYTHONPATH=/app:/app/cpp/build

# Expose port
EXPOSE 8000

# Add health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8000/health || exit 1

# Start command with gunicorn for production
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000"]
