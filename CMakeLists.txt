# MSVC / CMake build as an alternative to the primary zig build.
#
#   cmake -S . -B build -A x64 -DCLUMSY_SIGN=A
#   cmake --build build --config Release
#
# Links the bundled IUP import libraries (the *_dll16_lib copies) and WinDivert,
# then copies the required DLLs, the driver and config.txt next to clumsy.exe.
# The zig build (build.zig) remains the way the shipping binaries are produced.
cmake_minimum_required(VERSION 3.20)
project(clumsy C)

if(NOT WIN32)
    message(FATAL_ERROR "clumsy is Windows only")
endif()

set(CLUMSY_SIGN "A" CACHE STRING "WinDivert signing variant: A, B or C")
set_property(CACHE CLUMSY_SIGN PROPERTY STRINGS A B C)

# architecture -> bundled dependency folders
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(IUP_DIR "${CMAKE_SOURCE_DIR}/external/iup-3.30_Win64_dll16_lib")
    set(WD_DIR  "${CMAKE_SOURCE_DIR}/external/WinDivert-2.2.0-${CLUMSY_SIGN}/x64")
    set(RC_ARCH X64)
else()
    set(IUP_DIR "${CMAKE_SOURCE_DIR}/external/iup-3.30_Win32_dll16_lib")
    set(WD_DIR  "${CMAKE_SOURCE_DIR}/external/WinDivert-2.2.0-${CLUMSY_SIGN}/x86")
    set(RC_ARCH X86)
endif()

file(GLOB CLUMSY_SOURCES "${CMAKE_SOURCE_DIR}/src/*.c")

enable_language(RC)
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /I\"${CMAKE_SOURCE_DIR}/etc\" /d ${RC_ARCH}")

add_executable(clumsy WIN32 ${CLUMSY_SOURCES} "${CMAKE_SOURCE_DIR}/etc/clumsy.rc")

target_include_directories(clumsy PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${IUP_DIR}/include"
    "${WD_DIR}/../include")

target_compile_definitions(clumsy PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
target_compile_definitions(clumsy PRIVATE $<$<CONFIG:Debug>:_DEBUG> $<$<NOT:$<CONFIG:Debug>>:NDEBUG>)

target_link_directories(clumsy PRIVATE "${IUP_DIR}" "${WD_DIR}")
target_link_libraries(clumsy PRIVATE
    iup WinDivert
    comctl32 winmm ws2_32 kernel32 gdi32 comdlg32 uuid ole32 psapi advapi32 shell32 user32)

# the .rc already embeds the manifest, so stop the linker adding its own
set_target_properties(clumsy PROPERTIES
    LINK_FLAGS "/MANIFEST:NO /ENTRY:mainCRTStartup"
    LINK_FLAGS_DEBUG "/SUBSYSTEM:CONSOLE")

# stage runtime files next to the executable
set(RUNTIME_FILES
    "${IUP_DIR}/iup.dll"
    "${WD_DIR}/WinDivert.dll"
    "${CMAKE_SOURCE_DIR}/etc/config.txt")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND RUNTIME_FILES "${WD_DIR}/WinDivert64.sys")
else()
    list(APPEND RUNTIME_FILES "${WD_DIR}/WinDivert32.sys")
endif()

foreach(f ${RUNTIME_FILES})
    add_custom_command(TARGET clumsy POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${f}" "$<TARGET_FILE_DIR:clumsy>")
endforeach()
