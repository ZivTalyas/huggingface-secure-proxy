add_library(ml_interface STATIC
    MLInference.cpp
    MLInference.h
)

# Find required packages
find_package(nlohmann_json 3.2.0 REQUIRED)

# Set ONNX Runtime paths directly
set(ONNXRUNTIME_INCLUDE_DIR /usr/local/include)
set(ONNXRUNTIME_LIBRARY /usr/local/lib/libonnxruntime.so)


# Set include directories
target_include_directories(ml_interface PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ONNXRUNTIME_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(ml_interface PRIVATE
    ${ONNXRUNTIME_LIBRARY}
    nlohmann_json::nlohmann_json
)

# Add compile definitions
target_compile_definitions(ml_interface PRIVATE 
    ONNX_ML=1
    ONNX_NAMESPACE=onnx
)

# Install and export the target
install(TARGETS ml_interface
    EXPORT SecurityAnalyzerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)