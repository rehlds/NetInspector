# CLI11 for the tool's command line. Header only; the recorder does not use it.

include(FetchContent)

FetchContent_Declare(cli11
	URL "https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.4.2.tar.gz"
	URL_HASH SHA256=f2d893a65c3b1324c50d4e682c0cdc021dd0477ae2c048544f39eed6654b699a
	DOWNLOAD_EXTRACT_TIMESTAMP ON
)

set(CLI11_PRECOMPILED OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(CLI11_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cli11)

# Its headers are someone else's code: the tool's warning level stays off them
get_target_property(CLI11_INCLUDE_DIRS CLI11 INTERFACE_INCLUDE_DIRECTORIES)
set_target_properties(CLI11 PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${CLI11_INCLUDE_DIRS}")
