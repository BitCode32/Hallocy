# Hallocy
An advanced heap allocator for C.

# Introduction
Hallocy is an advanced C allocator library. This library implements the standard malloc, calloc, realloc, free, memset, memcopy, memmove and memcmp functions. The aim of this library is to be a better version of the standard C allocator by improving performance. Hallocy supports both Windows and Linux also keeping multithreading in mind.

# Features
The hallocy library offers the following features:
- Allocating and freeing memory
- Zeroing memory on allocation
- Reallocating more memory 
- Copying and moving memory
- Setting memory
- Comparing memory

# Installation
## Prerequisites
Ensure you have the following installed on your system:
* CMake (minimum version 3.10)
* A compatible C compiler (e.g., GCC or MSVC)

## Build Steps
1. Clone the repository:
```bash
git clone https://github.com/BitCode32/Hallocy.git
```

2. Navigate to the directory:
```bash
cd Hallocy
```

3. Create build directory and navigate to it:
```bash
mkdir Build && cd Build
```

4. Run CMake to configure project:
```bash
cmake ..
```

5. Build the project:
```bash
cmake --build . --config Release
```
To build in debug use:
```bash
cmake --build . 
```

## Running the engine
After building there will be an example application that you can find. The compiled executable will typically be located in the build directory:
```bash
.\HallocyApp.exe
``` 
The library file will also be include in the same folder usually as Hallocy.lib for windows or Hallocy.a for linux. To use the library file you will need to copy the Hallocy folder containing the header files and follow the setup process for a library in the build system you are using.  

# Usage
After setting up the project and including the Hallocy library you are ready to use the functions the library offers. The Hallocy library functions just like the standard c library functions you are used to. For example to allocate memory you can just use:
```c
char *my_memory = (char*)hallocy_malloc(10 * sizeof(char));
```
This will allocate 10 characters on the heap. You can directly manipulate this memory just like with the standard malloc. When you are done with the memory you should free it just like with the standard C library:
```c
hallocy_free(my_memory);
```
