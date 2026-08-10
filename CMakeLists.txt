cmake_minimum_required(VERSION 3.10)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
include(pkg-utils)
include(CPM)

pkg_get_version(CTL ${CMAKE_CURRENT_SOURCE_DIR}/include/ctl/detail/version VERSION)

project(ctl VERSION "${VERSION}" LANGUAGES C CXX)

option(CTL_BUILD_TESTS "Set to ON to build tests" OFF)

add_library(ctl INTERFACE)

CPMAddPackage("gh:ntoskrnl7/ext@0.5.18")
target_link_libraries(ctl INTERFACE ext)

target_include_directories(ctl INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if (CTL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()