#include "RootDetect.h"
#include "SecureAPI.h"
#include "Log.h"

#include <fcntl.h>
#include <dirent.h>

static const char *suBinaries[] = {
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/bin/su",
    "/system/bin/.ext/su",
    "/system/bin/failsafe/su",
    "/system/sd/xbin/su",
    "/system/usr/we-need-root/su",
    "/system/xbin/su",
    "/cache/su",
    "/data/su",
    "/dev/su"
};
static const char *magiskMounts[] = {
    "magisk",
    "core/mirror",
    "core/img"
};

const char *RootDetect::getName() {
    return "Root Detection";
}

eSeverity RootDetect::getSeverity() {
    return LOW;
}

bool RootDetect::execute() {
    LOGI("RootDetect::execute");
    if (detectSuBinaries()) {
        return true;
    }
    if (detectMagiskMount()) {
        return true;
    }

    return false;
}

bool RootDetect::detectSuBinaries() {
    for (const char *suBinary : suBinaries) {
        int fd = SecureAPI::openat(AT_FDCWD, suBinary, O_RDONLY, 0);
        if (fd != -1) {
            LOGI("RootDetect::execute su binary detected: %s", suBinary);
            SecureAPI::close(fd);
            return true;
        }

        if (SecureAPI::access(suBinary, F_OK) != -1 || errno != ENOENT) { // In some case, errno will says access denied when non-root user tries to access it.
            LOGI("RootDetect::execute su binary detected: %s", suBinary);
            return true;
        }
    }
    return false;
}

bool RootDetect::detectMagiskMount() {
    int fd = SecureAPI::openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY, 0);
    if (fd == -1) {
        return true;
    }

    char buf[512];
    while (SecureAPI::read(fd, buf, sizeof(buf)) > 0) {
        for (const char *magiskMount : magiskMounts) {
            if (strstr(buf, magiskMount)) {
                SecureAPI::close(fd);
                return true;
            }
        }
    }

    SecureAPI::close(fd);
    return false;
}