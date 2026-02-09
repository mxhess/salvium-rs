cmake_minimum_required(VERSION 3.18)
project(ExpoSalviumCrypto)

set(CMAKE_CXX_STANDARD 17)

# React Native JSI headers (provided by React Native)
find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)

# Pre-built Rust .so
add_library(salvium_crypto SHARED IMPORTED)
set_target_properties(salvium_crypto PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../prebuilt/android/${ANDROID_ABI}/libsalvium_crypto.so"
)

# JSI bridge module
add_library(${PROJECT_NAME} SHARED
    ../cpp/SalviumCryptoModule.cpp
    ../cpp/OnLoad.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ../cpp
    ../crates/salvium-crypto/include
)

target_link_libraries(${PROJECT_NAME}
    salvium_crypto
    ReactAndroid::jsi
    fbjni::fbjni
)
