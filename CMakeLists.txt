cmake_minimum_required(VERSION 3.16)
project(cvulns C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# NOTE: the vulnerable examples are deliberately built WITHOUT hardening
# (no stack protector, no FORTIFY_SOURCE) so the bugs behave as textbook
# examples. Never reuse these flags in real projects -- see docs in each file.
file(GLOB EXAMPLE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/ex*.c)

add_executable(cvulns src/main.c ${EXAMPLE_SOURCES})
target_include_directories(cvulns PRIVATE include)

if(MSVC)
  target_compile_options(cvulns PRIVATE /W3 /GS- /wd4996 /wd4477 /wd4313)
  target_compile_definitions(cvulns PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(cvulns PRIVATE -Wall -Wextra -O0 -g
    -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
    -Wno-format-security -Wno-stringop-overflow -Wno-array-bounds
    -Wno-use-after-free -Wno-free-nonheap-object -Wno-uninitialized
    -Wno-maybe-uninitialized -Wno-restrict -Wno-stringop-truncation)
endif()
if(WIN32)
  target_link_libraries(cvulns PRIVATE bcrypt)  # BCryptGenRandom for secure RNG
endif()

# Optional: sanitizer build to *detect* the bugs (Linux/macOS/clang-cl):
#   cmake -B build-asan -DCVULNS_SANITIZE=ON
option(CVULNS_SANITIZE "Build with ASan+UBSan" OFF)
if(CVULNS_SANITIZE AND NOT MSVC)
  target_compile_options(cvulns PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(cvulns PRIVATE -fsanitize=address,undefined)
endif()
