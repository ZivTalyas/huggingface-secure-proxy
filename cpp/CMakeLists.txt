cmake_minimum_required(VERSION 3.18)

# Add necessary paths for dependencies
list(APPEND CMAKE_PREFIX_PATH "/usr/lib/x86_64-linux-gnu/cmake/poppler") # For Poppler

project(SecurityEngine VERSION 1.0.0 LANGUAGES CXX)

# Set position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_PYTHON_BINDINGS "Build Python bindings" ON)

# Add source files for security analyzer library
set(SECURITY_ANALYZER_SOURCES
    securityAnalyzer/SecurityAnalyzer.cpp
    securityAnalyzer/SecurityAnalyzer.h
)

# Create the security analyzer library
add_library(security_analyzer ${SECURITY_ANALYZER_SOURCES})

target_include_directories(security_analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Find required packages
find_package(Boost 1.70 REQUIRED COMPONENTS regex)

# Use pkg-config to find Poppler
find_package(PkgConfig REQUIRED)
pkg_check_modules(POPPLER REQUIRED IMPORTED_TARGET poppler-cpp)

# Link dependencies
target_link_libraries(security_analyzer
    PRIVATE
        Boost::regex
        PkgConfig::POPPLER
)

# Python bindings
if(BUILD_PYTHON_BINDINGS)
    # Find Python with both Development and Interpreter components
    find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
    
    # Set Python include directories
    include_directories(${Python3_INCLUDE_DIRS})
    
    # Find pybind11
    find_package(pybind11 CONFIG REQUIRED)
    
    message(STATUS "Python3_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}")
    message(STATUS "Python3_LIBRARIES: ${Python3_LIBRARIES}")
    message(STATUS "Python3_EXECUTABLE: ${Python3_EXECUTABLE}")
    
    # Python module
    pybind11_add_module(security_analyzer_py
        bindings/python_bindings.cpp
    )
    
    target_include_directories(security_analyzer_py PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(security_analyzer_py
        PRIVATE
            security_analyzer
            pybind11::module
    )
    
    set_target_properties(security_analyzer_py PROPERTIES
        OUTPUT_NAME "security_analyzer"
        PREFIX ""
        SUFFIX ".so"
    )
    
    # Install Python module
    install(TARGETS security_analyzer_py
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/python
    )
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    
    if(GTEST_FOUND)
        message(STATUS "GTest found, building tests")
        # Add test subdirectory
        add_subdirectory(tests)
    else()
        message(STATUS "GTest not found, skipping tests")
    endif()
endif()

# Install targets
install(TARGETS security_analyzer
    EXPORT SecurityAnalyzerTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/securityAnalyzer/
    DESTINATION include/security_analyzer
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(EXPORT SecurityAnalyzerTargets
    FILE SecurityAnalyzerTargets.cmake
    NAMESPACE SecurityAnalyzer::
    DESTINATION lib/cmake/SecurityAnalyzer
)

# Check if we have the CMake modules needed for package configuration
find_package(CMakePackageConfigHelpers QUIET)
if(CMakePackageConfigHelpers_FOUND)
    # Config file
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/config/SecurityAnalyzerConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/SecurityAnalyzerConfig.cmake
        INSTALL_DESTINATION lib/cmake/SecurityAnalyzer
    )

    # Install config file
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/SecurityAnalyzerConfig.cmake
        DESTINATION lib/cmake/SecurityAnalyzer
    )
else()
    message(STATUS "CMakePackageConfigHelpers not found, skipping package configuration")
    # Create a basic config file
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/SecurityAnalyzerConfig.cmake
        "include(\"${CMAKE_CURRENT_BINARY_DIR}/SecurityAnalyzerTargets.cmake\")\n"
    )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/SecurityAnalyzerConfig.cmake
        DESTINATION lib/cmake/SecurityAnalyzer
    )
endif()

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


