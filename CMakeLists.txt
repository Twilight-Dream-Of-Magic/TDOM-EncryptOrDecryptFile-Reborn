#最低CMake版本
cmake_minimum_required(VERSION 3.5)

# 工程名 Project name
project (TDOM-EncryptOrDecryptFile-Reborn)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE release)

# set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#set(SOURCES
#    src/Main.cpp
#    src/IsFor_EODF_Reborn.hpp
#)

add_subdirectory(${PROJECT_SOURCE_DIR}/extra/mio)

if(MSVC)
	add_compile_options(/W4 /Zc:__cplusplus /utf-8)
else()
	if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11")
			message(FATAL_ERROR "GNU CXX compiler version is too small !")
		endif()
		add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
	endif()
endif()

add_executable(TDOM-EncryptOrDecryptFile-Reborn src/Main.cpp)

target_link_libraries(TDOM-EncryptOrDecryptFile-Reborn PRIVATE Threads::Threads)

target_include_directories(TDOM-EncryptOrDecryptFile-Reborn
	PRIVATE ${PROJECT_SOURCE_DIR}/include
	PRIVATE ${PROJECT_SOURCE_DIR}/extra/mio/include
	PRIVATE ${PROJECT_SOURCE_DIR}/extra/mio/single_include
)