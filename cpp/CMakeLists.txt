cmake_minimum_required(VERSION 3.10)

project(SecurityEngine VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add subdirectories
add_subdirectory(mlInterface)
add_subdirectory(textProcessor)

# Find required packages
find_package(Python3 REQUIRED COMPONENTS Development)
find_package(pybind11 REQUIRED CONFIG)
find_package(Boost REQUIRED COMPONENTS regex)
find_package(Poppler REQUIRED)

# Add source files
set(SOURCES
    SecurityAnalyzer.cpp
    SecurityAnalyzer.h
)

# Add library
target_sources(security_cpp PRIVATE ${SOURCES})

# Link libraries
target_link_libraries(security_cpp PRIVATE
    pybind11::module
    Boost::regex
    Poppler::Poppler
    text_processor
    ml_interface
)

# Include directories
include_directories(${PYTHON3_INCLUDE_DIRS})

# Set output directory
set_target_properties(security_cpp PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Create Python module
pybind11_add_module(security_cpp MODULE
    ${SOURCES}
)

# Link Python module
pybind11_extension(security_cpp
    ${SOURCES}
    LINK_LIBRARIES
        Boost::regex
        Poppler::Poppler
        text_processor
        ml_interface
)

# Install rules
install(TARGETS security_cpp
    RUNTIME DESTINATION ${PYTHON3_SITEARCH}
    LIBRARY DESTINATION ${PYTHON3_SITEARCH}
    ARCHIVE DESTINATION ${PYTHON3_SITEARCH}
)
