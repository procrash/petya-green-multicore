cmake_minimum_required(VERSION 2.8)
project (petya_green)

set (hdrs
    petya.h
    salsa20.h
    util.h
    gpu_code.h
    CustomOptionDescription.h
    OptionPrinter.h
    )

set (srcs
    salsa20.cpp
    main.cpp
    petya.cpp
    util.cpp
    gpu_code.cu
#    gpu_code.cpp
    CustomOptionDescription.cpp
    OptionPrinter.cpp
    )

set(CMAKE_BUILD_TYPE Debug)

# Pass options to NVCC
set(
    CUDA_NVCC_FLAGS
    ${CUDA_NVCC_FLAGS};
    -O3 -gencode arch=compute_30,code=sm_30 
#-lineinfo  -maxrregcount=16
    )

set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost 1.45.0 COMPONENTS system thread program_options filesystem regex date_time) 
find_package(CUDA QUIET REQUIRED)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS}) 
    cuda_add_executable (petya_green ${hdrs} ${srcs})
    target_link_libraries(petya_green 
	${Boost_LIBRARIES}
 	${Boost_SYSTEM_LIBRARY}
	)
endif()


#cuda_add_executable(
#    petya_green 
#    gpu_code.cu)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

IF (NOT APPLE)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBRARIES OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
ENDIF(NOT APPLE)

option (OUT_32BIT "Build 32-bit executable" OFF)

IF (OUT_32BIT)
    # To build x86 executable on x86-64 linux, install also the following: gcc-multilib g++-multilib
    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR "i686")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" CACHE STRING "c++ flags")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m32" CACHE STRING "c flags")
ENDIF(OUT_32BIT)







