# Find ONNX Runtime
#
# This module defines:
#  ONNXRUNTIME_FOUND - True if ONNX Runtime found
#  ONNXRUNTIME_INCLUDE_DIRS - Include directories for ONNX Runtime
#  ONNXRUNTIME_LIBRARIES - Libraries to link against for ONNX Runtime

find_path(ONNXRUNTIME_INCLUDE_DIR
    NAMES onnxruntime_cxx_api.h
    HINTS ${ONNXRUNTIME_ROOT} $ENV{ONNXRUNTIME_ROOT} /opt/onnxruntime
    PATH_SUFFIXES include/onnxruntime include
    DOC "ONNX Runtime include directory"
)

find_library(ONNXRUNTIME_LIBRARY
    NAMES onnxruntime
    HINTS ${ONNXRUNTIME_ROOT} $ENV{ONNXRUNTIME_ROOT} /opt/onnxruntime
    PATH_SUFFIXES lib
    DOC "ONNX Runtime library"
)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ONNXRuntime
    FOUND_VAR ONNXRUNTIME_FOUND
    REQUIRED_VARS ONNXRUNTIME_LIBRARY ONNXRUNTIME_INCLUDE_DIR
)

if(ONNXRUNTIME_FOUND)
    set(ONNXRUNTIME_LIBRARIES ${ONNXRUNTIME_LIBRARY})
    set(ONNXRUNTIME_INCLUDE_DIRS ${ONNXRUNTIME_INCLUDE_DIR})
    if(NOT TARGET ONNXRuntime::ONNXRuntime)
        add_library(ONNXRuntime::ONNXRuntime UNKNOWN IMPORTED)
        set_target_properties(ONNXRuntime::ONNXRuntime PROPERTIES
            IMPORTED_LOCATION "${ONNXRUNTIME_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${ONNXRUNTIME_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(ONNXRUNTIME_INCLUDE_DIR ONNXRUNTIME_LIBRARY)
