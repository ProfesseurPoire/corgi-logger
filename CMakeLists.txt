cmake_minimum_required(VERSION 3.13.0)

project(corgi-logger
    DESCRIPTION "Logging library"
    LANGUAGES CXX
    VERSION 1.0.0
    HOMEPAGE_URL "http://github.com/ProfesseurPoire/CorgiLogger")

set(CMAKE_DEBUG_POSTFIX d)

add_library(${PROJECT_NAME} "")
add_subdirectory(src)
add_subdirectory(include/corgi/logger)

if(MSVC)
target_compile_options(${PROJECT_NAME} PRIVATE -W4 -WX)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Werror)
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

set(install_folder lib${arch_suffix}/${PROJECT_NAME}-${PROJECT_VERSION}/)

target_include_directories(
    ${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Installing the library and exporting the targets

install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}Targets
    LIBRARY     DESTINATION lib
    RUNTIME     DESTINATION bin)

install(DIRECTORY include DESTINATION ./)

install(
    EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    DESTINATION lib/cmake/${PROJECT_NAME})

include(CMakePackageConfigHelpers)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION lib/cmake/${PROJECT_NAME}
)

write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION lib/cmake/${PROJECT_NAME}
)

#########################################
# Tests
#########################################

option(BUILD_TESTS "Build the tests" ON)

if(BUILD_TESTS)
enable_testing()
add_subdirectory(tests)
endif()