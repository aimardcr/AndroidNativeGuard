#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <dirent.h>
#include <syscall.h>

#include <asm/unistd.h>

#ifdef __arm__
#include "syscall/armeabi-v7a/syscall_arch.h"
#elif defined(__aarch64__)
#include "syscall/arm64-v8a/syscall_arch.h"
#elif defined(__i386__)
#include "syscall/x86/syscall_arch.h"
#elif defined(__x86_64__)
#include "syscall/x86_64/syscall_arch.h"
#endif

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

namespace SecureAPI {
    __attribute__((always_inline)) inline int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
        return (int) __syscall4(__NR_openat, dirfd, (long) pathname, flags, mode);
    }

    __attribute__((always_inline)) inline size_t read(int fd, void *buf, size_t count) {
        return (size_t) __syscall3(__NR_read, fd, (long) buf, count);
    }

    __attribute__((always_inline)) inline size_t write(int fd, const void *buf, size_t count) {
        return (size_t) __syscall3(__NR_write, fd, (long) buf, count);
    }

    __attribute__((always_inline)) inline off_t lseek(int fd, off_t offset, int whence) {
        return (off_t) __syscall3(__NR_lseek, fd, offset, whence);
    }

    __attribute__((always_inline)) inline int close(int fd) {
        return (int) __syscall1(__NR_close, fd);
    }

    __attribute__((always_inline)) inline int access(const char *pathname, int mode) {
#ifdef __arm__
        return (int) __syscall2(__NR_access, (long) pathname, mode);
#else
        return (int) __syscall3(__NR_faccessat, AT_FDCWD, (long) pathname, mode);
#endif
    }

    __attribute__((always_inline)) inline ssize_t getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
        return (ssize_t) __syscall3(__NR_getdents64, fd, (long) dirp, count);
    }

    __attribute__((always_inline)) inline int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
        return (int) __syscall4(__NR_readlinkat, dirfd, (long) pathname, (long) buf, bufsiz);
    }

    __attribute__((always_inline)) inline int inotify_init1(int flags) {
        return (int) __syscall1(__NR_inotify_init1, flags);
    }

    __attribute__((always_inline)) inline int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
        return (int) __syscall3(__NR_inotify_add_watch, fd, (long) pathname, mask);
    }

    __attribute__((always_inline)) inline int inotify_rm_watch(int fd, int wd) {
        return (int) __syscall2(__NR_inotify_rm_watch, fd, wd);
    }

    __attribute__((always_inline)) inline int strcmp(const char *s1, const char *s2) {
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }
        return *(const unsigned char *) s1 - *(const unsigned char *) s2;
    }

    __attribute__((always_inline)) inline int strncmp(const char *s1, const char *s2, size_t n) {
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

    __attribute__((always_inline)) inline char *strchr(const char *s, int c) {
        while (*s != (char) c) {
            if (!*s++) {
                return NULL;
            }
        }
        return (char *) s;
    }

    __attribute__((always_inline)) inline size_t strlen(const char *s) {
        const char *sc;
        for (sc = s; *sc != '\0'; ++sc) {
        }
        return sc - s;
    }

    __attribute__((always_inline)) inline int memcmp(const void *s1, const void *s2, size_t n) {
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

    __attribute__((always_inline)) inline void *memcpy(void *dest, const void *src, size_t n) {
        char *dp = (char *) dest;
        const char *sp = (const char *) src;
        while (n-- > 0) {
            *dp++ = *sp++;
        }
        return dest;
    }

    __attribute__((always_inline)) inline void *memset(void *s, int c, size_t n) {
        unsigned char *p = (unsigned char *) s;
        while (n-- > 0) {
            *p++ = (unsigned char) c;
        }
        return s;
    }

    __attribute__((always_inline)) inline const char *strstr(const char *haystack, const char *needle) {
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

}