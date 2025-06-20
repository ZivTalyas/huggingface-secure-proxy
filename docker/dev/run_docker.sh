#!/bin/bash

# Run the development Docker container
set -e  # Exit on error

# Clean up existing container
docker rm -f huggingface-secure-proxy-dev || true

# Run the development container with volume mounts and ports
docker run -d \
    --name huggingface-secure-proxy-dev \
    -v $(pwd):/app \
    -v $(pwd)/cpp/build:/app/cpp/build \
    -p 8000:8000 \
    -p 8080:8080 \
    huggingface-secure-proxy-dev:latest

# Show container status
echo "Container started successfully"
echo "Application running at: http://localhost:8000"
echo "Debug port: http://localhost:8080"

# Show logs in real-time
docker logs -f huggingface-secure-proxy-dev