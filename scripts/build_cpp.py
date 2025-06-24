#!/usr/bin/env python3
"""
Build script for the C++ security analyzer module.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a shell command and return its output."""
    print(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, cwd=cwd, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}", file=sys.stderr)
        return False

def build_cpp_module():
    """Build the C++ security analyzer module."""
    # Get project root directory
    project_root = Path(__file__).parent.parent
    cpp_dir = project_root / "cpp"
    build_dir = cpp_dir / "build"
    
    print(f"Building C++ module in {build_dir}")
    
    # Create build directory
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure with CMake
    cmake_cmd = [
        "cmake",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTS=ON",
        "-DBUILD_PYTHON_BINDINGS=ON",
        ".."
    ]
    
    if not run_command(cmake_cmd, cwd=build_dir):
        return False
    
    # Build the project
    if not run_command(["cmake", "--build", ".", "--config", "Release"], cwd=build_dir):
        return False
    
    # Run tests if requested
    if "RUN_TESTS" in os.environ:
        if not run_command(["ctest", "--output-on-failure"], cwd=build_dir):
            return False
    
    # Copy the built library to the expected location
    lib_name = "libsecurity_analyzer.so"
    lib_src = build_dir / lib_name
    lib_dest = project_root / "app" / "security" / lib_name
    
    if lib_src.exists():
        lib_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib_src, lib_dest)
        print(f"Copied {lib_name} to {lib_dest}")
    
    return True

if __name__ == "__main__":
    if not build_cpp_module():
        sys.exit(1)
