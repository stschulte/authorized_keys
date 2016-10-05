cmake_minimum_required (VERSION 2.8.11)
project (authorized_keys C)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra")

add_executable(authorized_keys src/authorized_keys.c)
