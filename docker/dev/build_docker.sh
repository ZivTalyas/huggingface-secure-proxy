#!/bin/bash

# Build the development Docker image
set -e  # Exit on error

# Clean up existing containers and images
docker-compose down -v || true
docker rmi huggingface-secure-proxy-dev:latest || true

# Build the development image
docker build \
    -t huggingface-secure-proxy-dev \
    -f docker/dev/Dockerfile \
    .

# Tag the image with current date
date_tag=$(date +%Y%m%d_%H%M%S)
docker tag huggingface-secure-proxy-dev:latest huggingface-secure-proxy-dev:$date_tag

# Show build summary
echo "Build completed successfully"
echo "Image tags:"
docker images | grep huggingface-secure-proxy-dev

# Clean up dangling images
docker image prune -f