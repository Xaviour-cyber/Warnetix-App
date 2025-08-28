cmake_minimum_required(VERSION 3.20)
project(warnetix_agent LANGUAGES CXX)

# === C++ standard ===
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === Optional OpenSSL ===
find_package(OpenSSL QUIET)
if (OpenSSL_FOUND)
  message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
endif()

# === yaml-cpp & libzip ===
find_package(yaml-cpp CONFIG REQUIRED)

find_package(libzip CONFIG QUIET)
if (NOT libzip_FOUND)
  find_package(unofficial-libzip CONFIG REQUIRED)
  set(LIBZIP_TARGET unofficial::libzip::zip)
else()
  set(LIBZIP_TARGET libzip::zip)
endif()

# === Sources ===
add_executable(warnetix_agent
  # lama
  src/main.cpp
  src/agent_config.cpp
  src/json_min.cpp
  src/entropy.cpp
  src/hash_sha256.cpp
  src/http_client_winhttp.cpp
  src/watcher_win.cpp
  src/retry_queue.cpp
  src/signature_fast.cpp
  src/io/file_util.cpp

  # engine
  src/core/config.cpp
  src/core/logger.cpp
  src/core/scan_archive.cpp
  src/core/stubs_link.cpp
  src/routing/router.cpp
  src/readers/ZipReader.cpp
)

target_include_directories(warnetix_agent PRIVATE include)

# === Compile defs & warnings ===
# pakai target_* (lebih modern drpd add_definitions)
target_compile_definitions(warnetix_agent PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
if (OpenSSL_FOUND)
  target_compile_definitions(warnetix_agent PRIVATE HAVE_OPENSSL=1)
endif()

if (MSVC)
  target_compile_options(warnetix_agent PRIVATE /W4 /permissive-)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_compile_options(warnetix_agent PRIVATE -Wall -Wextra -Wpedantic)
endif()

# === Link libraries ===
target_link_libraries(warnetix_agent PRIVATE
  yaml-cpp::yaml-cpp           # gunakan target modern (hindari 'yaml-cpp' yang deprecated)
  ${LIBZIP_TARGET}
)

# Windows system libs (aman kalau build di Windows)
if (WIN32)
  target_link_libraries(warnetix_agent PRIVATE winhttp bcrypt ws2_32 shlwapi)
endif()

# OpenSSL opsional
if (OpenSSL_FOUND)
  target_link_libraries(warnetix_agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
