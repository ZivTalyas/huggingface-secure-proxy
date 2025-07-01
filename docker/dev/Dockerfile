# Build stage for C++ module
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    cmake \
    nlohmann-json3-dev \
    libboost-all-dev \
    libpoppler-cpp-dev \
    libpoppler-private-dev \
    pkg-config \
    python3-pip \
    python3-venv \
    python3.11-dev \
    libpython3.11-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python build dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir "pybind11[global]" numpy

# Copy source code
COPY . /src

# Set working directory for build
WORKDIR /src/cpp

# Build and install C++ module
RUN python3 setup.py install

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    libpoppler-cpp0v5 \
    libboost-regex1.74.0 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled C++ module and all other installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Set working directory
WORKDIR /app

# Copy Python requirements and application code from the source in the builder stage
COPY --from=builder /src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=builder /src/app /app
COPY --from=builder /src/run.py .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose backend port
EXPOSE 8001
