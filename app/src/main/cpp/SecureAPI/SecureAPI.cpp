#include "SecureAPI.h"

#ifdef __arm__
#include "syscall/armeabi-v7a/syscall_arch.h"
#elif defined(__aarch64__)
#include "syscall/arm64-v8a/syscall_arch.h"
#elif defined(__i386__)
#include "syscall/x86/syscall_arch.h"
#elif defined(__x86_64__)
#include "syscall/x86_64/syscall_arch.h"
#endif

int SecureAPI::openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    return (int) __syscall4(__NR_openat, dirfd, (long) pathname, flags, mode);
}

size_t SecureAPI::read(int fd, void *buf, size_t count) {
    return (size_t) __syscall3(__NR_read, fd, (long) buf, count);
}

size_t SecureAPI::write(int fd, const void *buf, size_t count) {
    return (size_t) __syscall3(__NR_write, fd, (long) buf, count);
}

off_t SecureAPI::lseek(int fd, off_t offset, int whence) {
    return (off_t) __syscall3(__NR_lseek, fd, offset, whence);
}

int SecureAPI::close(int fd) {
    return (int) __syscall1(__NR_close, fd);
}

int SecureAPI::access(const char *pathname, int mode) {
#ifdef __arm__
    return (int) __syscall2(__NR_access, (long) pathname, mode);
#else
    return ::access(pathname, mode); // TODO: Find better solution
#endif
}

ssize_t SecureAPI::getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    return (ssize_t) __syscall3(__NR_getdents64, fd, (long) dirp, count);
}

int SecureAPI::readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    return (int) __syscall4(__NR_readlinkat, dirfd, (long) pathname, (long) buf, bufsiz);
}

int SecureAPI::strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *) s1 - *(const unsigned char *) s2;
}

int SecureAPI::strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) {
        return 0;
    }
    do {
        if (*s1 != *s2++) {
            return (*(const unsigned char *) s1 - *(const unsigned char *) --s2);
        }
        if (*s1++ == 0) {
            break;
        }
    } while (--n != 0);
    return 0;
}

const char *SecureAPI::strstr(const char *haystack, const char *needle) {
    size_t needle_len = SecureAPI::strlen(needle);
    if (!needle_len) {
        return haystack;
    }
    const char *p = haystack;
    while ((p = SecureAPI::strchr(p, *needle)) != NULL) {
        if (!SecureAPI::memcmp(p, needle, needle_len)) {
            return p;
        }
        p++;
    }
    return NULL;
}

char *SecureAPI::strchr(const char *s, int c) {
    while (*s != (char) c) {
        if (!*s++) {
            return NULL;
        }
    }
    return (char *) s;
}

size_t SecureAPI::strlen(const char *s) {
    const char *sc;
    for (sc = s; *sc != '\0'; ++sc) {
    }
    return sc - s;
}

int SecureAPI::memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *) s1, *p2 = (const unsigned char *) s2;
    while (n-- > 0) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        ++p1;
        ++p2;
    }
    return 0;
}

void *SecureAPI::memcpy(void *dest, const void *src, size_t n) {
    char *dp = (char *) dest;
    const char *sp = (const char *) src;
    while (n-- > 0) {
        *dp++ = *sp++;
    }
    return dest;
}

void *SecureAPI::memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *) s;
    while (n-- > 0) {
        *p++ = (unsigned char) c;
    }
    return s;
}