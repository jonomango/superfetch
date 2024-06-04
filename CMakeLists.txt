cmake_minimum_required(VERSION 3.17)

project(
  superfetch
  DESCRIPTION "Translate virtual addresses to physical addresses from usermode"
  HOMEPAGE_URL "https://github.com/jonomango/superfetch"
  LANGUAGES CXX C
)

add_library(
  superfetch INTERFACE
  "include/superfetch/superfetch.h"
  "include/superfetch/nt.h"
)

target_include_directories(
  superfetch INTERFACE
  "include"
)

target_link_libraries(
  superfetch INTERFACE
  ntdll
)

# C++23, C11.
set_target_properties(
  superfetch PROPERTIES
  CXX_STANDARD 23
  CXX_STANDARD_REQUIRED ON
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
)
