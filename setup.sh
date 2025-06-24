#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🚀 Setting up Secure Input Validation Proxy${NC}"

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${GREEN}Creating .env file from example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}Please edit the .env file with your configuration${NC}"
else
    echo -e "${GREEN}.env file already exists, skipping creation${NC}"
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}Docker Compose is not installed. Please install Docker Compose.${NC}"
    exit 1
fi

# Make run.py executable
chmod +x run.py

# Build and start services
echo -e "${GREEN}Building and starting services...${NC}"

# Use the full path to docker-compose.yml
DOCKER_COMPOSE_CMD="docker-compose -f docker/docker-compose.yml"

# Build services
echo -e "${YELLOW}Building Docker images...${NC}"
$DOCKER_COMPOSE_CMD build

# Start services
echo -e "${YELLOW}Starting services...${NC}"
$DOCKER_COMPOSE_CMD up -d

# Show service status
echo -e "\n${GREEN}✅ Setup complete!${NC}"
echo -e "\n${YELLOW}📋 Service Status:${NC}"
$DOCKER_COMPOSE_CMD ps

echo -e "\n${YELLOW}🚀 Services are starting up. Run ${GREEN}./healthcheck.sh${YELLOW} to verify all services are running.${NC}"
echo -e "\nServices are now running:"
echo -e "- Frontend API: ${GREEN}http://localhost:8000${NC}"
echo -e "- Backend API:  ${GREEN}http://localhost:8001${NC}"
echo -e "- Prometheus:   ${GREEN}http://localhost:9090${NC}"
echo -e "- Grafana:      ${GREEN}http://localhost:3000${NC} (admin/admin)"
echo -e "\nUse ${YELLOW}./run.py${NC} to manage services:"
echo -e "  ${YELLOW}./run.py logs${NC}     - View logs"
echo -e "  ${YELLOW}./run.py stop${NC}     - Stop services"
echo -e "  ${YELLOW}./run.py restart${NC}  - Restart services"

echo -e "${YELLOW}🚀 Happy coding!${NC}"
