# SPDX-License-Identifier: BSD-3-Clause

zephyr_include_directories(../../../include)

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(greybus)

file(GLOB_RECURSE app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
