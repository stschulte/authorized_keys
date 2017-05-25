cmake_minimum_required (VERSION 2.8.11)
project (lookup-ssh-pubkey C)

SET(PROGRAM_NAME "lookup-ssh-pubkey")
SET(VERSION_MAJOR 0)
SET(VERSION_MINOR 1)
SET(VERSION_PATCH 0)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra")
set(CMAKE_INSTALL_SYSCONFDIR "etc" CACHE PATH "read-only single-machine data (etc)")
set(CMAKE_INSTALL_KEYDIR "${CMAKE_INSTALL_SYSCONFDIR}/ssh-public-keys.d" CACHE PATH "path to store public keys (etc/ssh-public-keys.d)")

if(IS_ABSOLUTE ${CMAKE_INSTALL_KEYDIR})
  set(CMAKE_INSTALL_FULL_KEYDIR  "${CMAKE_INSTALL_KEYDIR}")
else()
  set(CMAKE_INSTALL_FULL_KEYDIR "/${CMAKE_INSTALL_KEYDIR}")
endif()

configure_file( "${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_SOURCE_DIR}/src/config.h" )
add_executable(lookup-ssh-pubkey src/lookup-ssh-pubkey.c)

install(TARGETS lookup-ssh-pubkey RUNTIME DESTINATION bin)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_KEYDIR})
