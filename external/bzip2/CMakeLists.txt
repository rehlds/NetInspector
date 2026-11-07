# bzip2 for the tool, which decompresses the compressed reliable streams of recordings.
# The recorder does not use it: cmake/NetInspector.cmake and msvc/NetInspector.vcxitems
# never reach this directory.

include(FetchContent)

FetchContent_Declare(bzip2
	URL "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz"
	URL_HASH SHA256=ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269
	DOWNLOAD_EXTRACT_TIMESTAMP ON
)

# The archive has no CMake project of its own; the library is defined below
FetchContent_MakeAvailable(bzip2)

enable_language(C)

add_library(bzip2 STATIC
	"${bzip2_SOURCE_DIR}/blocksort.c"
	"${bzip2_SOURCE_DIR}/bzlib.c"
	"${bzip2_SOURCE_DIR}/compress.c"
	"${bzip2_SOURCE_DIR}/crctable.c"
	"${bzip2_SOURCE_DIR}/decompress.c"
	"${bzip2_SOURCE_DIR}/huffman.c"
	"${bzip2_SOURCE_DIR}/randtable.c"
)

target_include_directories(bzip2 SYSTEM PUBLIC "${bzip2_SOURCE_DIR}")
target_compile_definitions(bzip2 PRIVATE _CRT_SECURE_NO_WARNINGS)

if(MSVC)
	target_compile_options(bzip2 PRIVATE /W0)
else()
	target_compile_options(bzip2 PRIVATE -w)
endif()
