#include "RootDetect.h"
#include "SecureAPI.h"
#include "Log.h"
#include "obfuscate.h"

#include <fcntl.h>
#include <dirent.h>

static const char *suBinaries[] = {
    AY_OBFUSCATE("/data/local/su"),
    AY_OBFUSCATE("/data/local/bin/su"),
    AY_OBFUSCATE("/data/local/xbin/su"),
    AY_OBFUSCATE("/sbin/su"),
    AY_OBFUSCATE("/su/bin/su"),
    AY_OBFUSCATE("/system/bin/su"),
    AY_OBFUSCATE("/system/bin/.ext/su"),
    AY_OBFUSCATE("/system/bin/failsafe/su"),
    AY_OBFUSCATE("/system/sd/xbin/su"),
    AY_OBFUSCATE("/system/usr/we-need-root/su"),
    AY_OBFUSCATE("/system/xbin/su"),
    AY_OBFUSCATE("/cache/su"),
    AY_OBFUSCATE("/data/su"),
    AY_OBFUSCATE("/dev/su")
};
static const char *magiskMounts[] = {
    AY_OBFUSCATE("magisk"),
    AY_OBFUSCATE("core/mirror"),
    AY_OBFUSCATE("core/img")
};

const char *RootDetect::getName() {
    return AY_OBFUSCATE("Root Detection");
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
        if (fd > 0) {
            LOGI("RootDetect::execute su binary detected: %s", suBinary);
            SecureAPI::close(fd);
            return true;
        }

        if (SecureAPI::access(suBinary, F_OK) == 0) {
            LOGI("RootDetect::execute su binary detected: %s", suBinary);
            return true;
        }
    }
    return false;
}

bool RootDetect::detectMagiskMount() {
    int fd = SecureAPI::openat(AT_FDCWD, AY_OBFUSCATE("/proc/self/mounts"), O_RDONLY, 0);
    if (fd == -1) {
        return true;
    }

    char buf[512];
    while (SecureAPI::read(fd, buf, sizeof(buf)) > 0) {
        for (const char *magiskMount : magiskMounts) {
            if (strstr(buf, magiskMount)) {
                LOGI("RootDetect::execute magisk mount detected: %s", magiskMount);
                SecureAPI::close(fd);
                return true;
            }
        }
    }

    SecureAPI::close(fd);
    return false;
}