#最低CMake版本
cmake_minimum_required(VERSION 3.5)

# 工程名 Project name
project (TDOM-EncryptOrDecryptFile-Reborn)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_BUILD_TYPE release)

# set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(SOURCES
	src/Main.cpp
	src/IsFor_EODF_Reborn.hpp
)

add_subdirectory(${PROJECT_SOURCE_DIR}/extra/mio)

message(STATUS "CMAKE_CXX_FLAGS = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE = ${CMAKE_CXX_FLAGS_DEBUG}")

# Detect the compiler
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11")
		message(FATAL_ERROR "GNU CXX compiler version is too small !")
	endif ()
	set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during debug builds." FORCE)
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during release builds." FORCE)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	set(CMAKE_CXX_FLAGS_DEBUG "/std:c++20 /Zi /Od /EHsc /MTd /Zc:__cplusplus /utf-8 /bigobj /W4 /D_ITERATOR_DEBUG_LEVEL=2")
    set(CMAKE_CXX_FLAGS_RELEASE "/std:c++20 /O2 /EHsc /MT /Zc:__cplusplus /utf-8 /bigobj /W4 /D_ITERATOR_DEBUG_LEVEL=0")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during debug builds." FORCE)
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during release builds." FORCE)
else()
	message(WARNING "Unknown compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()

message(STATUS "CMAKE_CXX_FLAGS = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE = ${CMAKE_CXX_FLAGS_DEBUG}")

add_executable(${PROJECT_NAME} source-code/Main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

target_include_directories(${PROJECT_NAME}
	PRIVATE ${PROJECT_SOURCE_DIR}/include
	PRIVATE ${PROJECT_SOURCE_DIR}/extra/mio/include
	PRIVATE ${PROJECT_SOURCE_DIR}/extra/mio/single_include
)
