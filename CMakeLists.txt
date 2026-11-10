cmake_minimum_required(VERSION 3.21)

project(NetInspector
	DESCRIPTION "Records and inspects GoldSrc network traffic"
	HOMEPAGE_URL "https://github.com/rehlds/NetInspector"
	LANGUAGES CXX
)

option(NETINSPECTOR_BUILD_TOOLS "Build the netinspector command line tool" ${PROJECT_IS_TOP_LEVEL})
option(NETINSPECTOR_BUILD_TESTS "Build the unit tests (fetches GoogleTest)" ${PROJECT_IS_TOP_LEVEL})
option(LINK_STATIC_MSVC_RT "Link the MSVC runtime statically" ON)
option(LINK_STATIC_STDCPP "Link libstdc++ and libgcc into the tool statically" OFF)
option(ENABLE_ASAN "Build the tool and the tests with AddressSanitizer" OFF)
option(ENABLE_UBSAN "Build the tool and the tests with UndefinedBehaviorSanitizer" OFF)

# For every target of this build, so GoogleTest and bzip2 share the runtime of the tool and
# the tests. Programs that embed the recorder never run this file.
if(LINK_STATIC_MSVC_RT)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include("cmake/NetInspector.cmake")
include("cmake/CompileOptions.cmake")
include("cmake/AppVersion.cmake")

find_package(Threads REQUIRED)

# The recorder as a library for the tool and the tests; embedding programs compile the sources
add_library(netinspector_core STATIC ${NETINSPECTOR_SOURCES})
target_include_directories(netinspector_core PUBLIC ${NETINSPECTOR_INCLUDE_DIRS})
target_link_libraries(netinspector_core PUBLIC Threads::Threads)
netinspector_configure_target(netinspector_core)

# What reading a recording needs beyond the recorder: never compiled into embedding programs
add_library(netinspector_decoder STATIC
	"src/netinspector/decoder/bit_reader.cpp"
	"src/netinspector/decoder/channel_receiver.cpp"
	"src/netinspector/decoder/delta_reader.cpp"
	"src/netinspector/decoder/message_decoder.cpp"
	"src/netinspector/decoder/server_packet.cpp"
	"src/netinspector/decoder/session_tables.cpp"
)
target_link_libraries(netinspector_decoder PUBLIC netinspector_core)
netinspector_configure_target(netinspector_decoder)

if(NETINSPECTOR_BUILD_TOOLS)
	add_subdirectory(external/bzip2)
	add_subdirectory(external/cli11)
	add_subdirectory(tools/netinspector)
endif()

if(NETINSPECTOR_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
endif()
