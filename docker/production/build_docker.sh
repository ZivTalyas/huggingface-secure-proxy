#!/bin/bash

# Build the production Docker image
set -e  # Exit on error

# Clean up existing containers and images
docker-compose down -v || true
docker rmi huggingface-secure-proxy-prod:latest || true

# Build the production image
docker build \
    -t huggingface-secure-proxy-prod \
    -f docker/production/Dockerfile \
    .

# Tag the image with current date
date_tag=$(date +%Y%m%d_%H%M%S)
docker tag huggingface-secure-proxy-prod:latest huggingface-secure-proxy-prod:$date_tag

# Show build summary
echo "Build completed successfully"
echo "Image tags:"
docker images | grep huggingface-secure-proxy-prod

# Clean up dangling images
docker image prune -f

# Push to registry if specified
if [ ! -z "$DOCKER_REGISTRY" ]; then
    docker tag huggingface-secure-proxy-prod:latest $DOCKER_REGISTRY/huggingface-secure-proxy-prod:latest
    docker tag huggingface-secure-proxy-prod:latest $DOCKER_REGISTRY/huggingface-secure-proxy-prod:$date_tag
    docker push $DOCKER_REGISTRY/huggingface-secure-proxy-prod:latest
    docker push $DOCKER_REGISTRY/huggingface-secure-proxy-prod:$date_tag
fi