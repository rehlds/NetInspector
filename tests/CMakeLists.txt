include(FetchContent)

# 1.15 is the last GoogleTest release that builds as C++14
FetchContent_Declare(googletest
	URL "https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz"
	URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
	DOWNLOAD_EXTRACT_TIMESTAMP ON
)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
# The runtime comes from CMAKE_MSVC_RUNTIME_LIBRARY; GoogleTest must not pick its own
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(netinspector_tests
	anonymizer_tests.cpp
	channel_tests.cpp
	decoder_tests.cpp
	format_tests.cpp
	recorder_tests.cpp
)

target_link_libraries(netinspector_tests PRIVATE netinspector_decoder GTest::gtest_main)
netinspector_configure_target(netinspector_tests)

include(GoogleTest)
gtest_discover_tests(netinspector_tests DISCOVERY_MODE PRE_TEST)
