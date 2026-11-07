# Warnings and sanitizers for NetInspector's own targets: the core library, the tool, the tests.
# Applied per target, never globally, so nothing here reaches a project that only takes the
# recorder sources through cmake/NetInspector.cmake.

function(netinspector_configure_target target)
	target_compile_features(${target} PRIVATE cxx_std_14)
	set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)

	if(MSVC)
		target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
		target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
	else()
		target_compile_options(${target} PRIVATE -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion)

		if(ENABLE_ASAN)
			target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
			target_link_options(${target} PRIVATE -fsanitize=address)
		endif()

		if(ENABLE_UBSAN)
			target_compile_options(${target} PRIVATE -fsanitize=undefined -fno-sanitize-recover=undefined)
			target_link_options(${target} PRIVATE -fsanitize=undefined)
		endif()
	endif()
endfunction()
