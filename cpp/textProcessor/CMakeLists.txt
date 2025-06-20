add_library(text_processor STATIC
    TextProcessor.cpp
    TextProcessor.h
)

# Find required packages
find_package(Boost REQUIRED COMPONENTS regex)
find_package(Poppler REQUIRED)

# Link libraries
target_link_libraries(text_processor PRIVATE
    Boost::regex
    Poppler::Poppler
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${Poppler_INCLUDE_DIRS})