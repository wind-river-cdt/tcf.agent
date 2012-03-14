# -*- cmake -*-

cmake_minimum_required(VERSION 2.8)

set(CMAKE_COLOR_MAKEFILE OFF)

set(TCF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(TCF_LIB_NAME tcf-agent)

if (NOT WIN32)
  if(NOT TCF_OPSYS)
    set(TCF_OPSYS "GNU/Linux")
  endif()
  if(NOT TCF_MACHINE)
    set(TCF_MACHINE "x86_64")
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  set(MULTI_THREADED_COMPILE_FLAGS "-pthreads")
  set(MULTI_THREADED_LINK_LIBS pthread rt)
elseif(APPLE)
  set(MULTI_THREADED_COMPILE_FLAGS "-pthread -D_REENTRANT")
  set(MULTI_THREADED_LINK_FLAGS "")
  set(MULTI_THREADED_LINK_LIBS pthread)
elseif(UNIX)
  set(MULTI_THREADED_COMPILE_FLAGS "-pthread -D_REENTRANT")
  set(MULTI_THREADED_LINK_FLAGS "")
  set(MULTI_THREADED_LINK_LIBS pthread rt)
  set(UUID_LIB_NAME uuid)
elseif(WIN32)
  set(SOCKET_LINK_LIBS ws2_32 iphlpapi)
endif()

include(../cmake-tcf-lib.txt)

message(STATUS "operating system:" ${TCF_OPSYS})
message(STATUS "machine:" ${TCF_MACHINE})

add_executable(agent tcf/main/main.c)
target_link_libraries(agent ${TCF_LIB_NAME})
