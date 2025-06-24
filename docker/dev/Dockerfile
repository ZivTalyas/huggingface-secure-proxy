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
    pip3 install --no-cache-dir pybind11[global] numpy

# Download and install ONNX Runtime
ARG ONNXRUNTIME_VERSION=1.15.1
ARG ONNXRUNTIME_ARCH=x64
RUN wget https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/onnxruntime-linux-${ONNXRUNTIME_ARCH}-${ONNXRUNTIME_VERSION}.tgz -O onnxruntime.tgz && \
    tar -zxvf onnxruntime.tgz && \
    cp -r onnxruntime-linux-${ONNXRUNTIME_ARCH}-${ONNXRUNTIME_VERSION}/include/* /usr/local/include/ && \
    cp -r onnxruntime-linux-${ONNXRUNTIME_ARCH}-${ONNXRUNTIME_VERSION}/lib/* /usr/local/lib/ && \
    rm -rf onnxruntime.tgz onnxruntime-linux-${ONNXRUNTIME_ARCH}-${ONNXRUNTIME_VERSION} && \
    ldconfig

# Set working directory
WORKDIR /build

# Copy C++ source files
# COPY cpp/ ./cpp/

# Build C++ module
# RUN mkdir -p cpp/build && \
#     cd cpp/build && \
#     cmake .. && \
#     make

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy ONNX runtime libs from builder stage
# COPY --from=builder /build/cpp/build/security_analyzer.*.so .
COPY --from=builder /usr/local/lib/libonnxruntime.so* /usr/local/lib/
RUN ldconfig

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy C++ module from builder
# COPY --from=builder /build/cpp/build/security_analyzer.*.so .

# Copy application code
COPY ./app /app/
COPY run.py .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose backend port
EXPOSE 8001
