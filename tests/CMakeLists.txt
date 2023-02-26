cmake_minimum_required(VERSION 3.13.0)

project(
    CorgiLoggerTest 
    DESCRIPTION "Test the CorgiLogger features"
    LANGUAGES CXX )

add_executable(${PROJECT_NAME} "")

add_subdirectory(src)

# Needed for x64 architecture so it looks inside a lib64 repository
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_compile_definitions(${PROJECT_NAME} PUBLIC LOG_LEVEL=3)

find_package(corgi-test)

target_link_libraries(${PROJECT_NAME} PRIVATE corgi-logger corgi-test)
