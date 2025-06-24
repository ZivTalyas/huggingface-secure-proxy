#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Load environment variables safely
if [ -f .env ]; then
    # Use a temporary file to handle special characters
    grep -v '^#' .env | grep -v '^$' | sed 's/^export //' > /tmp/env_vars
    while IFS= read -r line; do
        # Skip lines with format strings that might cause issues
        if ! echo "$line" | grep -q '='; then
            continue
        fi
        var_name="${line%%=*}"
        # Skip problematic variables
        if [[ "$var_name" == "LOG_FORMAT" || "$var_name" == *"*"* ]]; then
            continue
        fi
        # Only export if not already set
        if [ -z "${!var_name:-}" ]; then
            export "$line"
        fi
    done < /tmp/env_vars
    rm -f /tmp/env_vars
fi

# Default values if not set in .env
FRONTEND_PORT=${FRONTEND_PORT:-8000}
BACKEND_PORT=${BACKEND_PORT:-8001}
REDIS_PORT=${REDIS_PORT:-6379}

check_service() {
    local name=$1
    local url=$2
    local command=$3
    
    echo -n "Checking ${name}... "
    
    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}✓ RUNNING${NC}"
        return 0
    else
        echo -e "${RED}✗ NOT RUNNING${NC}"
        return 1
    fi
}

echo -e "${YELLOW}🔍 Running health checks...${NC}\n"

# Check Docker services
check_service "Docker" "docker ps" "docker ps > /dev/null"
check_service "Docker Compose" "docker-compose -f docker/docker-compose.yml ps" "docker-compose -f docker/docker-compose.yml ps > /dev/null"

# Check Redis
check_service "Redis" "redis-cli ping" "docker-compose -f docker/docker-compose.yml exec -T redis redis-cli ping | grep -q PONG"

# Check Backend API
check_service "Backend API" "http://localhost:${BACKEND_PORT}/health" "curl -s -f http://localhost:${BACKEND_PORT}/health | grep -q 'ok'"

# Check Frontend API
check_service "Frontend API" "http://localhost:${FRONTEND_PORT}/status" "curl -s -f http://localhost:${FRONTEND_PORT}/status | grep -q 'ok'"

# Check Prometheus if enabled
if [ "${PROMETHEUS_ENABLED:-false}" = "true" ]; then
    PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
    check_service "Prometheus" "http://localhost:${PROMETHEUS_PORT}/-/ready" "curl -s -f http://localhost:${PROMETHEUS_PORT}/-/ready | grep -q 'Prometheus'"
fi

echo -e "\n${YELLOW}📊 Service Status:${NC}"
echo -e "Frontend API: http://localhost:${FRONTEND_PORT}/status"
echo -e "Backend API:  http://localhost:${BACKEND_PORT}/health"
echo -e "Redis:        localhost:${REDIS_PORT}"

if [ "${PROMETHEUS_ENABLED:-false}" = "true" ]; then
    echo -e "Prometheus:   http://localhost:${PROMETHEUS_PORT}"
    echo -e "Grafana:      http://localhost:3000"
fi

echo -e "\n${GREEN}✅ Health check completed!${NC}"
