# The recorder for projects that compile it into their own binaries. The sources
# build with the including project's flags and toolchain; CMake 3.1 is enough.
#
#   include(dep/netinspector/cmake/NetInspector.cmake)
#   target_sources(engine PRIVATE ${NETINSPECTOR_SOURCES})
#   target_include_directories(engine PRIVATE ${NETINSPECTOR_INCLUDE_DIRS})
#
# On Linux the binary links pthread.

get_filename_component(NETINSPECTOR_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(NETINSPECTOR_SOURCE_ROOT "${NETINSPECTOR_ROOT}/src/netinspector")

set(NETINSPECTOR_INCLUDE_DIRS
	"${NETINSPECTOR_ROOT}/include"
	"${NETINSPECTOR_ROOT}/src"
)

set(NETINSPECTOR_SOURCES
	"${NETINSPECTOR_SOURCE_ROOT}/anonymizer.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/format.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/reader.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/common/siphash.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/common/strtools.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/protocol/channel.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/protocol/connectionless.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/protocol/info_string.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/protocol/munge.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/recorder/endpoint_registry.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/recorder/entry_queue.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/recorder/entry_writer.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/recorder/output_file.cpp"
	"${NETINSPECTOR_SOURCE_ROOT}/recorder/recorder.cpp"
)

if(WIN32)
	set(NETINSPECTOR_PLATFORM "windows")
else()
	set(NETINSPECTOR_PLATFORM "posix")
endif()

foreach(NETINSPECTOR_PLATFORM_UNIT clock condition_variable mutex random thread)
	list(APPEND NETINSPECTOR_SOURCES "${NETINSPECTOR_SOURCE_ROOT}/platform/${NETINSPECTOR_PLATFORM}/${NETINSPECTOR_PLATFORM_UNIT}.cpp")
endforeach()
