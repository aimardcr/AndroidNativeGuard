#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <dlfcn.h>

uint32_t crc32(uint8_t *data, size_t size);