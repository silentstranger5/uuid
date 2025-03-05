cmake_minimum_required(VERSION 3.10.0)
project(uuid VERSION 0.1.0 LANGUAGES C)

add_executable(uuid uuid.c splitmix64.c xoroshiro.c clockseq.c macaddress.c sha.c)