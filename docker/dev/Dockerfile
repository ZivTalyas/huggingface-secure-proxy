# Development Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    make \
    g++ \
    wget \
    unzip \
    nlohmann-json3-dev \
    libboost-all-dev \
    libpoppler-cpp-dev \
    libpoppler-dev \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/include/nlohmann \
    && ln -sf /usr/include/nlohmann/json.hpp /usr/local/include/nlohmann/

# Install ONNX Runtime
RUN mkdir -p /opt/onnxruntime && \
    cd /opt/onnxruntime && \
    wget https://github.com/microsoft/onnxruntime/releases/download/v1.15.1/onnxruntime-linux-x64-1.15.1.tgz && \
    tar -xzf onnxruntime-linux-x64-1.15.1.tgz --strip-components=1 && \
    rm onnxruntime-linux-x64-1.15.1.tgz && \
    echo "/opt/onnxruntime/lib" > /etc/ld.so.conf.d/onnxruntime.conf && \
    ldconfig

# Set environment variables for ONNX Runtime
ENV ONNXRUNTIME_ROOT_DIR=/opt/onnxruntime
ENV ONNXRUNTIME_INCLUDE_DIR=/opt/onnxruntime/include/onnxruntime/core/session
ENV ONNXRUNTIME_LIBRARY_DIR=/opt/onnxruntime/lib

# Initialize environment variables without referencing potentially undefined variables
ENV LD_LIBRARY_PATH=/opt/onnxruntime/lib
ENV PATH=$PATH:/opt/onnxruntime/bin
ENV CMAKE_PREFIX_PATH=/opt/onnxruntime

# Update ldconfig to include ONNX Runtime libraries
RUN echo "/opt/onnxruntime/lib" > /etc/ld.so.conf.d/onnxruntime.conf && \
    ldconfig

# Install Python dependencies
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

# Set environment variables
ENV PYTHONPATH=/app

# Set working directory for the application
WORKDIR /app/app

# Copy application code
COPY app /app/app

# Expose ports
EXPOSE 8000 8080

# Default command (starts a shell)
CMD ["/bin/bash"]
