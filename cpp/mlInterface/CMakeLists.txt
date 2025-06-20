add_library(ml_interface STATIC
    MLInference.cpp
    MLInference.h
)

# Find required packages
find_package(ONNXRuntime REQUIRED)
find_package(nlohmann_json REQUIRED)

# Link libraries
target_link_libraries(ml_interface PRIVATE
    ONNXRuntime::ONNXRuntime
    nlohmann_json::nlohmann_json
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${ONNXRuntime_INCLUDE_DIRS})
include_directories(${nlohmann_json_INCLUDE_DIRS})