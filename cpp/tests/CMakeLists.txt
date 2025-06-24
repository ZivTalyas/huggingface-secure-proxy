cmake_minimum_required(VERSION 3.10)
project(security_analyzer_tests)

# Enable testing
enable_testing()

# Find required packages
find_package(Poppler REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/..
    ${POPPLER_INCLUDE_DIRS}
)

# Add test executable
add_executable(security_analyzer_tests
    test_security_analyzer.cpp
)

# Link libraries
target_link_libraries(security_analyzer_tests
    PRIVATE
    security_analyzer
    ${POPPLER_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)

# Add test
add_test(NAME security_analyzer_tests COMMAND security_analyzer_tests)

# Copy test files
file(COPY
    ${CMAKE_CURRENT_SOURCE_DIR}/test_data/
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test_data
)
