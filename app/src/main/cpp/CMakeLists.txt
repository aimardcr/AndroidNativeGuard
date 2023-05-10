cmake_minimum_required(VERSION 3.22.1)

project(NativeGuard)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -fno-exceptions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdata-sections -ffunction-sections")

if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -marm")
endif ()

add_library(NativeGuard SHARED
        main.cpp
        Utils/ElfImg.cpp
        Modules/AntiDebug/AntiDebug.cpp
        Modules/FridaDetect/FridaDetect.cpp
        Modules/RiGisk/RiGisk.cpp
        Modules/RootDetect/RootDetect.cpp
        Modules/AntiDump/AntiDump.cpp
        Modules/AntiLibPatch/AntiLibPatch.cpp)

target_include_directories(NativeGuard PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/SecureAPI
        ${CMAKE_CURRENT_SOURCE_DIR}/SecureAPI/syscall/${ANDROID_ABI}
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils
        ${CMAKE_CURRENT_SOURCE_DIR}/Modules)

target_link_libraries(NativeGuard log)