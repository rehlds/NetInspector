add_executable(netinspector
	main.cpp
	command.cpp
	endpoint_directory.cpp
	info_report.cpp
	json_writer.cpp
	messages_report.cpp
	findings.cpp
	health_report.cpp
	overflow_report.cpp
	threats_report.cpp
	report_clock.cpp
	stream_decompressor.cpp
	timeline_report.cpp
	traffic_walker.cpp
)

target_include_directories(netinspector PRIVATE "${PROJECT_BINARY_DIR}/generated")
target_link_libraries(netinspector PRIVATE netinspector_decoder bzip2 CLI11::CLI11)
netinspector_configure_target(netinspector)

if(LINK_STATIC_STDCPP AND NOT MSVC)
	target_link_options(netinspector PRIVATE -static-libstdc++ -static-libgcc)
endif()

install(TARGETS netinspector RUNTIME DESTINATION .)
install(FILES "${PROJECT_SOURCE_DIR}/README.md" "${PROJECT_SOURCE_DIR}/LICENSE" DESTINATION .)
