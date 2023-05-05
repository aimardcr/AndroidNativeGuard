#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <dirent.h>
#include <syscall.h>

#include <asm/unistd.h>

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

namespace SecureAPI {
    int openat(int dirfd, const char *pathname, int flags, mode_t mode);
    size_t read(int fd, void *buf, size_t count);
    size_t write(int fd, const void *buf, size_t count);
    off_t lseek(int fd, off_t offset, int whence);
    int close(int fd);

    int access(const char *pathname, int mode);

    ssize_t getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

    int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);

    int strcmp(const char *s1, const char *s2);
    int strncmp(const char *s1, const char *s2, size_t n);
    const char *strstr(const char *haystack, const char *needle);
    char *strchr(const char *s, int c);

    size_t strlen(const char *s);
    int memcmp(const void *s1, const void *s2, size_t n);
    void *memcpy(void *dest, const void *src, size_t n);
    void *memset(void *s, int c, size_t n);

}