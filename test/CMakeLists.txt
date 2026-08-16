cmake_minimum_required(VERSION 3.10)

include(../cmake/CPM.cmake)

if (NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
  set(CMAKE_BUILD_TYPE "Debug")
  message("CMAKE_BUILD_TYPE (default) : " ${CMAKE_BUILD_TYPE})
else()
  message("CMAKE_BUILD_TYPE : " ${CMAKE_BUILD_TYPE})
endif()

project(unittest LANGUAGES C CXX)

CPMAddPackage(NAME ctl SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

if (MSVC_VERSION LESS_EQUAL 1700)
  if (MSVC_VERSION GREATER_EQUAL 1600)
    add_definitions(-DGTEST_HAS_TR1_TUPLE=0)
  endif()
  CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.7.0
    VERSION 1.7.0
    OPTIONS "INSTALL_GTEST OFF" "gtest_force_shared_crt"
  )
  include_directories("${gtest_SOURCE_DIR}/include")
else()
  CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.10.0
    VERSION 1.10.0
    OPTIONS "INSTALL_GTEST OFF" "gtest_force_shared_crt"
  )
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(gtest INTERFACE -Wno-deprecated-copy)
    target_compile_options(gtest_main INTERFACE -Wno-deprecated-copy)
endif()

# Calling file(GLOB ...) twice with the same variable makes the second call
# overwrite the result of the first, which is why main.cpp used to be left out
# of the list. Everything is gathered in a single call instead. gtest_main is
# not linked because main.cpp provides main; a static library only supplies
# symbols that are still unresolved, so the two never actually collided, but
# stating where main comes from is clearer.
file(GLOB SOURCE_FILES
  ${CMAKE_CURRENT_LIST_DIR}/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/aes/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/aria/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/lea/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/mode/*.cpp
  ${CMAKE_CURRENT_LIST_DIR}/random/*.cpp
)

add_executable(unittest ${SOURCE_FILES})
target_link_libraries(unittest ctl gtest)

if (CXX_USE_BOOST)
  add_definitions(-DCXX_USE_BOOST)
  find_package(Boost 1.69.0 REQUIRED COMPONENTS thread system chrono)
  include_directories(${Boost_INCLUDE_DIRS})
  target_link_directories(unittest PRIVATE ${Boost_LIBRARY_DIRS})
endif()

get_property(CXX_STANDARD_SPECIFIED TARGET unittest PROPERTY CXX_STANDARD SET)
if (CXX_STANDARD_SPECIFIED)
  get_property(CXX_STANDARD_VAR TARGET unittest PROPERTY CXX_STANDARD)
  message("CXX_STANDARD : " ${CXX_STANDARD_VAR})
else()
  set_property(TARGET unittest PROPERTY CXX_STANDARD 17)
  get_property(CXX_STANDARD_VAR TARGET unittest PROPERTY CXX_STANDARD)
  message("CXX_STANDARD (default): " ${CXX_STANDARD_VAR})
endif()
set_property(TARGET unittest PROPERTY CXX_STANDARD_REQUIRED ON)

if (WIN32)
elseif(APPLE)
elseif(UNIX)
  target_link_libraries(unittest rt)
endif()

enable_testing()

# On macOS the tests run under LC_ALL=C, which stops string conversion from
# working. LC_ALL is therefore set to en_US.UTF-8 when the tests are run so
# that string conversion behaves as expected.
if (APPLE)
  add_test(NAME unittest COMMAND ${CMAKE_COMMAND} -E env LC_ALL=en_US.UTF-8 ${CMAKE_BINARY_DIR}/unittest)
else()
  add_test(NAME unittest COMMAND unittest)
endif()
