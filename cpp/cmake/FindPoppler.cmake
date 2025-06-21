# Find Poppler
#
# This module defines:
#  POPPLER_FOUND - True if Poppler found
#  POPPLER_INCLUDE_DIRS - Include directories for Poppler
#  POPPLER_LIBRARIES - Libraries to link against for Poppler
#  POPPLER_CPP_FOUND - True if Poppler C++ interface found
#  POPPLER_CPP_INCLUDE_DIRS - Include directories for Poppler C++
#  POPPLER_CPP_LIBRARIES - Libraries to link against for Poppler C++

find_package(PkgConfig QUIET)
pkg_check_modules(PC_POPPLER QUIET poppler)

# Find include directory
find_path(POPPLER_INCLUDE_DIR
    NAMES poppler/PDFDoc.h
    HINTS ${PC_POPPLER_INCLUDE_DIRS} ${PC_POPPLER_INCLUDEDIR}
    PATH_SUFFIXES poppler
)

# Find library
find_library(POPPLER_LIBRARY
    NAMES poppler
    HINTS ${PC_POPPLER_LIBRARY_DIRS} ${PC_POPPLER_LIBDIR}
)

# Find C++ interface
find_path(POPPLER_CPP_INCLUDE_DIR
    NAMES poppler/cpp/poppler-document.h
    HINTS ${PC_POPPLER_INCLUDE_DIRS} ${PC_POPPLER_INCLUDEDIR}
    PATH_SUFFIXES poppler/cpp
)

find_library(POPPLER_CPP_LIBRARY
    NAMES poppler-cpp
    HINTS ${PC_POPPLER_LIBRARY_DIRS} ${PC_POPPLER_LIBDIR}
)

include(FindPackageHandleStandardArgs)

# Handle the QUIETLY and REQUIRED arguments and set POPPLER_FOUND
find_package_handle_standard_args(Poppler
    FOUND_VAR POPPLER_FOUND
    REQUIRED_VARS POPPLER_LIBRARY POPPLER_INCLUDE_DIR
    VERSION_VAR PC_POPPLER_VERSION
)

# Set variables
if(POPPLER_FOUND)
    set(POPPLER_LIBRARIES ${POPPLER_LIBRARY})
    set(POPPLER_INCLUDE_DIRS ${POPPLER_INCLUDE_DIR})
    set(POPPLER_DEFINITIONS ${PC_POPPLER_CFLAGS_OTHER})

    if(NOT TARGET Poppler::Poppler)
        add_library(Poppler::Poppler UNKNOWN IMPORTED)
        set_target_properties(Poppler::Poppler PROPERTIES
            IMPORTED_LOCATION "${POPPLER_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${POPPLER_INCLUDE_DIR}"
            INTERFACE_COMPILE_OPTIONS "${PC_POPPLER_CFLAGS_OTHER}"
        )
    endif()
endif()

# Handle C++ interface
if(POPPLER_CPP_INCLUDE_DIR AND POPPLER_CPP_LIBRARY)
    set(POPPLER_CPP_FOUND TRUE)
    set(POPPLER_CPP_LIBRARIES ${POPPLER_CPP_LIBRARY})
    set(POPPLER_CPP_INCLUDE_DIRS ${POPPLER_CPP_INCLUDE_DIR})

    if(NOT TARGET Poppler::Cpp)
        add_library(Poppler::Cpp UNKNOWN IMPORTED)
        set_target_properties(Poppler::Cpp PROPERTIES
            IMPORTED_LOCATION "${POPPLER_CPP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${POPPLER_CPP_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES Poppler::Poppler
        )
    endif()
endif()

mark_as_advanced(
    POPPLER_INCLUDE_DIR
    POPPLER_LIBRARY
    POPPLER_CPP_INCLUDE_DIR
    POPPLER_CPP_LIBRARY
)
