# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/kuba/CLionProjects/libPISSD

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/kuba/CLionProjects/libPISSD/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/PISSD.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/PISSD.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/PISSD.dir/flags.make

CMakeFiles/PISSD.dir/PISSD.cpp.o: CMakeFiles/PISSD.dir/flags.make
CMakeFiles/PISSD.dir/PISSD.cpp.o: ../PISSD.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kuba/CLionProjects/libPISSD/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/PISSD.dir/PISSD.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/PISSD.dir/PISSD.cpp.o -c /Users/kuba/CLionProjects/libPISSD/PISSD.cpp

CMakeFiles/PISSD.dir/PISSD.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PISSD.dir/PISSD.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kuba/CLionProjects/libPISSD/PISSD.cpp > CMakeFiles/PISSD.dir/PISSD.cpp.i

CMakeFiles/PISSD.dir/PISSD.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PISSD.dir/PISSD.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kuba/CLionProjects/libPISSD/PISSD.cpp -o CMakeFiles/PISSD.dir/PISSD.cpp.s

CMakeFiles/PISSD.dir/PISSD.cpp.o.requires:

.PHONY : CMakeFiles/PISSD.dir/PISSD.cpp.o.requires

CMakeFiles/PISSD.dir/PISSD.cpp.o.provides: CMakeFiles/PISSD.dir/PISSD.cpp.o.requires
	$(MAKE) -f CMakeFiles/PISSD.dir/build.make CMakeFiles/PISSD.dir/PISSD.cpp.o.provides.build
.PHONY : CMakeFiles/PISSD.dir/PISSD.cpp.o.provides

CMakeFiles/PISSD.dir/PISSD.cpp.o.provides.build: CMakeFiles/PISSD.dir/PISSD.cpp.o


# Object files for target PISSD
PISSD_OBJECTS = \
"CMakeFiles/PISSD.dir/PISSD.cpp.o"

# External object files for target PISSD
PISSD_EXTERNAL_OBJECTS =

libPISSD.dylib: CMakeFiles/PISSD.dir/PISSD.cpp.o
libPISSD.dylib: CMakeFiles/PISSD.dir/build.make
libPISSD.dylib: CMakeFiles/PISSD.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/kuba/CLionProjects/libPISSD/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libPISSD.dylib"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/PISSD.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/PISSD.dir/build: libPISSD.dylib

.PHONY : CMakeFiles/PISSD.dir/build

CMakeFiles/PISSD.dir/requires: CMakeFiles/PISSD.dir/PISSD.cpp.o.requires

.PHONY : CMakeFiles/PISSD.dir/requires

CMakeFiles/PISSD.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/PISSD.dir/cmake_clean.cmake
.PHONY : CMakeFiles/PISSD.dir/clean

CMakeFiles/PISSD.dir/depend:
	cd /Users/kuba/CLionProjects/libPISSD/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kuba/CLionProjects/libPISSD /Users/kuba/CLionProjects/libPISSD /Users/kuba/CLionProjects/libPISSD/cmake-build-debug /Users/kuba/CLionProjects/libPISSD/cmake-build-debug /Users/kuba/CLionProjects/libPISSD/cmake-build-debug/CMakeFiles/PISSD.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/PISSD.dir/depend

