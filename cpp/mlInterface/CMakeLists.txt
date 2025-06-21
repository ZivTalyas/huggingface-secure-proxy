add_library(ml_interface STATIC
    MLInference.cpp
    MLInference.h
)

# Find required packages
find_package(nlohmann_json 3.2.0 REQUIRED)

# Set include directories
target_include_directories(ml_interface PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ONNXRUNTIME_INCLUDE_DIR}
    /usr/include
)

# Link libraries
target_link_libraries(ml_interface PRIVATE
    ${ONNXRUNTIME_LIBRARY_DIR}/libonnxruntime.so
    nlohmann_json
)

# Add compile definitions
target_compile_definitions(ml_interface PRIVATE 
    ONNX_ML=1
    ONNX_NAMESPACE=onnx
)