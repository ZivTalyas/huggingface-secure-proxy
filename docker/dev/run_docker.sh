#!/bin/bash

# Run the development Docker container
set -e  # Exit on error

# Get absolute path to the project root
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONTAINER_NAME="huggingface-secure-proxy-dev"

# Stop and remove existing container if it exists
echo "=== Stopping and removing existing container if it exists ==="
docker rm -f $CONTAINER_NAME 2>/dev/null || true

# Run the development container with volume mounts and ports
echo -e "\n=== Starting development container ==="
echo "Mounting $PROJECT_ROOT/app to /app/app"
echo "Mounting $PROJECT_ROOT/cpp to /app/cpp"

# Check if container already exists
if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    echo "Container $CONTAINER_NAME already exists. Removing..."
    docker rm -f $CONTAINER_NAME >/dev/null
fi

# Create build directory in advance
mkdir -p "$PROJECT_ROOT/cpp/build"

echo -e "\n=== Starting Development Environment ==="
echo "Container name: $CONTAINER_NAME"
echo "Mounted directories:"
echo "  - /app/app -> $PROJECT_ROOT/app"
echo "  - /app/cpp -> $PROJECT_ROOT/cpp"
echo -e "\n=== Available Commands ==="
echo "1. Build C++ code:"
echo "   cd /app/cpp/build"
echo "   cmake .."
echo "   make"
echo -e "\n2. Start Python application:"
echo "   cd /app/app"
echo "   uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
echo -e "\n3. Exit the container:"
echo "   exit"
echo -e "\n=== Starting Container ==="

# Start the interactive container
docker run -it \
    --name $CONTAINER_NAME \
    -p 8000:8000 \
    -p 8080:8080 \
    -v "$PROJECT_ROOT/app":/app/app \
    -v "$PROJECT_ROOT/cpp":/app/cpp \
    -e PYTHONPATH=/app:/app/cpp/build \
    huggingface-secure-proxy-dev:latest

# Show container status after exit
echo -e "\n=== Container Status ==="
docker ps -a --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Show logs if container is still running
if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
    echo -e "\n=== Logs (Ctrl+C to stop following logs) ==="
    docker logs -f $CONTAINER_NAME
fi
docker logs -f huggingface-secure-proxy-dev