add_library(text_processor STATIC
    TextProcessor.cpp
    TextProcessor.h
)

# Find required packages
find_package(Boost REQUIRED COMPONENTS regex)

# Use pkg-config to find Poppler
find_package(PkgConfig REQUIRED)
pkg_check_modules(POPPLER REQUIRED IMPORTED_TARGET poppler-cpp)

# Link libraries
target_link_libraries(text_processor PRIVATE
    Boost::regex
    PkgConfig::POPPLER
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${Boost_INCLUDE_DIRS})

# Install and export the target
install(TARGETS text_processor
    EXPORT SecurityAnalyzerTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)