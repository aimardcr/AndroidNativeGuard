cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -marm")
endif ()

add_library(NativeGuard SHARED
        main.cpp
        SecureAPI/SecureAPI.cpp
        Utils/ElfImg.cpp
        Utils/Utils.cpp
        Modules/AntiDebug/AntiDebug.cpp
        Modules/FridaDetect/FridaDetect.cpp
        Modules/RiGisk/RiGisk.cpp
        Modules/RootDetect/RootDetect.cpp)

target_include_directories(NativeGuard PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/SecureAPI
        ${CMAKE_CURRENT_SOURCE_DIR}/SecureAPI/syscall/${ANDROID_ABI}
        ${CMAKE_CURRENT_SOURCE_DIR}/Utils
        ${CMAKE_CURRENT_SOURCE_DIR}/Modules)

target_link_libraries(NativeGuard log)

#add_custom_command( TARGET NativeGuard
#        POST_BUILD
#        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -R .comment -g -S -d --strip-unneeded ${CMAKE_HOME_DIRECTORY}/../../../build/intermediates/cmake/${CMAKE_BUILD_TYPE}/obj/${ANDROID_ABI}/libNativeGuard.so
#        COMMENT "Stripped native library")