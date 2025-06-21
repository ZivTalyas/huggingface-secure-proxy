#!/bin/bash

# Build the development Docker image
set -e  # Exit on error

echo "=== Building huggingface-secure-proxy development image ==="

# Get absolute path to the project root
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# Build the development image
echo "Building Docker image..."
docker build \
    -t huggingface-secure-proxy-dev:latest \
    -f "$PROJECT_ROOT/docker/dev/Dockerfile" \
    "$PROJECT_ROOT"

# Tag the image with current date
date_tag=$(date +%Y%m%d_%H%M%S)
docker tag huggingface-secure-proxy-dev:latest huggingface-secure-proxy-dev:$date_tag

# Show build summary
echo "\n=== Build Summary ==="
docker images | grep huggingface-secure-proxy-dev

echo "\nTo run the container:"
echo "  docker run -p 8000:8000 -p 8080:8080 -v $(pwd)/app:/app/app -v $(pwd)/cpp:/app/cpp huggingface-secure-proxy-dev"
docker image prune -f