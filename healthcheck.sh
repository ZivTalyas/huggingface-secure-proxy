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

# Determine protocol based on SSL certificate availability
if [ -f "docker/dev/certs/cert.pem" ] && [ -f "docker/dev/certs/key.pem" ]; then
    PROTOCOL="https"
    FRONTEND_HTTPS_PORT=${FRONTEND_HTTPS_PORT:-8443}
    BACKEND_HTTPS_PORT=${BACKEND_HTTPS_PORT:-8444}
    CURL_OPTS="-k" # Accept self-signed certificates
    echo -e "${YELLOW}🔒 Using HTTPS (SSL certificates found)${NC}"
else
    PROTOCOL="http"
    CURL_OPTS=""
    echo -e "${YELLOW}🔓 Using HTTP (no SSL certificates found)${NC}"
fi

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
check_service "Docker Compose" "docker-compose -f docker/dev/docker-compose.yml ps" "docker-compose -f docker/dev/docker-compose.yml ps > /dev/null"

# Check Redis
check_service "Redis" "redis-cli ping" "docker-compose -f docker/dev/docker-compose.yml exec -T redis redis-cli ping | grep -q PONG"

# Check Backend API
if [ "$PROTOCOL" = "https" ]; then
    check_service "Backend API (HTTPS)" "https://localhost:${BACKEND_HTTPS_PORT}/health" "curl -s -f ${CURL_OPTS} https://localhost:${BACKEND_HTTPS_PORT}/health | grep -q 'healthy'"
    # Also check HTTP port if it's available
    check_service "Backend API (HTTP)" "http://localhost:${BACKEND_PORT}/health" "curl -s -f http://localhost:${BACKEND_PORT}/health | grep -q 'healthy'"
else
    check_service "Backend API" "http://localhost:${BACKEND_PORT}/health" "curl -s -f http://localhost:${BACKEND_PORT}/health | grep -q 'healthy'"
fi

# Check Frontend API
if [ "$PROTOCOL" = "https" ]; then
    check_service "Frontend API (HTTPS)" "https://localhost:${FRONTEND_HTTPS_PORT}/status" "curl -s -f ${CURL_OPTS} https://localhost:${FRONTEND_HTTPS_PORT}/status | grep -q 'available'"
    # Also check HTTP port if it's available
    check_service "Frontend API (HTTP)" "http://localhost:${FRONTEND_PORT}/status" "curl -s -f http://localhost:${FRONTEND_PORT}/status | grep -q 'available'"
else
    check_service "Frontend API" "http://localhost:${FRONTEND_PORT}/status" "curl -s -f http://localhost:${FRONTEND_PORT}/status | grep -q 'available'"
fi

# Check Prometheus if enabled
if [ "${PROMETHEUS_ENABLED:-false}" = "true" ]; then
    PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
    check_service "Prometheus" "http://localhost:${PROMETHEUS_PORT}/-/ready" "curl -s -f http://localhost:${PROMETHEUS_PORT}/-/ready | grep -q 'Prometheus'"
fi

echo -e "\n${YELLOW}📊 Service Status:${NC}"
if [ "$PROTOCOL" = "https" ]; then
    echo -e "Frontend API (HTTPS): https://localhost:${FRONTEND_HTTPS_PORT}/status"
    echo -e "Frontend API (HTTP):  http://localhost:${FRONTEND_PORT}/status"
    echo -e "Backend API (HTTPS):  https://localhost:${BACKEND_HTTPS_PORT}/health"
    echo -e "Backend API (HTTP):   http://localhost:${BACKEND_PORT}/health"
    echo -e "Redis:                localhost:${REDIS_PORT}"
    echo -e ""
    echo -e "${YELLOW}🔒 Access your application at:${NC}"
    echo -e "  - https://localhost:${FRONTEND_HTTPS_PORT} (HTTPS - Recommended)"
    echo -e "  - http://localhost:${FRONTEND_PORT} (HTTP - Fallback)"
else
    echo -e "Frontend API: http://localhost:${FRONTEND_PORT}/status"
    echo -e "Backend API:  http://localhost:${BACKEND_PORT}/health"
    echo -e "Redis:        localhost:${REDIS_PORT}"
    echo -e ""
    echo -e "${YELLOW}🔓 Access your application at:${NC}"
    echo -e "  - http://localhost:${FRONTEND_PORT}"
fi

if [ "${PROMETHEUS_ENABLED:-false}" = "true" ]; then
    echo -e "Prometheus:   http://localhost:${PROMETHEUS_PORT}"
    echo -e "Grafana:      http://localhost:3000"
fi

echo -e "\n${GREEN}✅ Health check completed!${NC}"
