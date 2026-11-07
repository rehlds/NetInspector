# Linux builds without setting up a machine: GCC, Clang, Ninja, a CMake new enough for the
# presets, and the 32-bit libraries scripts/build_baseline.sh builds against
FROM ubuntu:24.04

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates git cmake ninja-build g++ clang gcc-multilib g++-multilib binutils gdb \
	&& rm -rf /var/lib/apt/lists/*
