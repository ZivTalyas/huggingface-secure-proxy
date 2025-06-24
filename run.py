#!/usr/bin/env python3
"""
Secure Input Validation Proxy - Main Entry Point

This script provides commands to manage the application using Docker Compose.
"""
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Optional

# Project root directory
PROJECT_ROOT = Path(__file__).parent.absolute()
DOCKER_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"

# Docker Compose command with the correct file path
def docker_compose_cmd(args: List[str]) -> int:
    """Run a docker compose command with the correct compose file."""
    cmd = ["docker-compose", "-f", str(DOCKER_COMPOSE)] + args
    print(f"Running: {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=PROJECT_ROOT)

def start_services():
    """Start all services using Docker Compose"""
    return docker_compose_cmd(["up", "--build", "-d"])

def stop_services():
    """Stop all services"""
    return docker_compose_cmd(["down"])

def restart_services():
    """Restart all services"""
    stop_services()
    return start_services()

def show_logs(service: str = None):
    """Show logs for all or a specific service"""
    cmd = ["logs", "--follow", "--tail=100"]
    if service:
        cmd.append(service)
    return docker_compose_cmd(cmd)

def build_services():
    """Build all services"""
    return docker_compose_cmd(["build"])

def main():
    """Main function to manage the application"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Input Validation Proxy")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Start command
    start_parser = subparsers.add_parser("start", help="Start all services")
    start_parser.add_argument(
        "--build", action="store_true", help="Build images before starting"
    )
    
    # Stop command
    subparsers.add_parser("stop", help="Stop all services")
    
    # Restart command
    restart_parser = subparsers.add_parser("restart", help="Restart all services")
    restart_parser.add_argument(
        "--build", action="store_true", help="Rebuild images before restarting"
    )
    
    # Logs command
    logs_parser = subparsers.add_parser("logs", help="Show service logs")
    logs_parser.add_argument("service", nargs="?", help="Service name (optional)")
    
    # Build command
    subparsers.add_parser("build", help="Build all services")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == "start":
        cmd = ["up", "-d"]
        if args.build:
            cmd.insert(1, "--build")
        return docker_compose_cmd(cmd)
    elif args.command == "stop":
        return stop_services()
    elif args.command == "restart":
        if args.build:
            build_services()
        return restart_services()
    elif args.command == "logs":
        return show_logs(args.service)
    elif args.command == "build":
        return build_services()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
