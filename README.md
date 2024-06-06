# superfetch
Simple library for translating virtual addresses to physical addresses from usermode.

## Example usage

```cpp
#include <superfetch/superfetch.h>

int main() {
  auto const mm = spf::memory_map::current();
  if (!mm) {
    // Do something with mm.error()
  }
  
  // Any kernel virtual address.
  void const* const virt = ...;
  
  std::uint64_t const phys = mm->translate(virt);
  if (!phys) {
    // Do something...
  }
  
  std::printf("%p -> %zX\n", virt, phys);
}
```

## Installation

To use `superfetch`, simply add the `include` directory to your project and include
`superfetch/superfetch.h`.

### CMake

If you are using [CMake](https://cmake.org/), add this repository as a
subdirectory and link to the `superfetch` target library.

```cmake
add_subdirectory(path/to/superfetch/repo/dir)
target_link_libraries(my_project_target superfetch)
```

