#!/bin/bash

# Run the production Docker container
set -e  # Exit on error

# Clean up existing container
docker rm -f huggingface-secure-proxy-prod || true

# Run the production container with optimized settings
docker run -d \
    --name huggingface-secure-proxy-prod \
    --restart unless-stopped \
    -p 8000:8000 \
    -e PYTHONPATH=/app:/app/cpp/build \
    -e PORT=8000 \
    huggingface-secure-proxy-prod:latest

# Show container status
echo "Container started successfully"
echo "Application running at: http://localhost:8000"

# Monitor container health
echo "Waiting for container to start..."
sleep 5
docker ps | grep huggingface-secure-proxy-prod

# Check health endpoint
echo "Checking health endpoint..."
health_check=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
if [ "$health_check" = "200" ]; then
    echo "Health check passed"
else
    echo "Health check failed with status: $health_check"
    exit 1
fi