# Development Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install development tools
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    vim \
    curl \
    wget \
    libicu-dev \
    libpoppler-dev \
    libboost-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python development dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Set up volume mounts for development
VOLUME /app
VOLUME /app/cpp/build

# Install C++ dependencies
WORKDIR /app/cpp
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make

# Set up environment variables
ENV PYTHONPATH=/app:/app/cpp/build

# Expose ports
EXPOSE 8000
EXPOSE 8080  # Debug port

# Start command with hot reload
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
