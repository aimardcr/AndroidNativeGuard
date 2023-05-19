#include "AntiDebug.h"
#include "SecureAPI.h"
#include "Log.h"

#include <fcntl.h>
#include <dirent.h>

AntiDebug::AntiDebug(void (*callback)()) : onDebuggerDetected(callback) {

}

const char *AntiDebug::getName()  {
    return "Debugger Detection";
}

eSeverity AntiDebug::getSeverity() {
    return HIGH;
}

bool AntiDebug::execute() {
    LOGI("AntiDebug::execute");
    if (scanStatus()) {
        return true;
    }
    if (scanTaskStatuses()) {
        return true;
    }
    LOGI("AntiDebug::execute false");
    return false;
}

bool AntiDebug::scanStatus() {
    LOGI("AntiDebug::scanStatus");
    int fd = SecureAPI::openat(AT_FDCWD, "/proc/self/status", O_RDONLY, 0);
    if (fd == -1) {
        return true;
    }
    LOGI("AntiDebug::scanStatus fd: %d", fd);

    if (checkTracerPid(fd)) {
        SecureAPI::close(fd);
        return true;
    }

    SecureAPI::close(fd);
    return false;
}

bool AntiDebug::scanTaskStatuses() {
    LOGI("AntiDebug::scanTaskStatuses");
    int fd = SecureAPI::openat(AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY, 0);
    if (fd == -1) {
        return true;
    }

    struct linux_dirent64 *dirp;
    char buf[512];
    int nread;

    while ((nread = SecureAPI::getdents64(fd, (struct linux_dirent64 *) buf, sizeof(buf))) > 0) {
        for (int bpos = 0; bpos < nread;) {
            dirp = (struct linux_dirent64 *) (buf + bpos);
            if (dirp->d_type == DT_DIR) {
                LOGI("AntiDebug::scanTaskStatuses dirp->d_name: %s", dirp->d_name);
                if (!SecureAPI::strcmp(dirp->d_name, ".") || !SecureAPI::strcmp(dirp->d_name, "..")) {
                    bpos += dirp->d_reclen;
                    continue;
                }

                char statusPath[512];
                sprintf(statusPath, "/proc/self/task/%s/status", dirp->d_name);
                int statusFd = SecureAPI::openat(AT_FDCWD, statusPath, O_RDONLY, 0);
                LOGI("AntiDebug::scanTaskStatuses statusPath: %s | statusFd: %d", statusPath, statusFd);
                if (statusFd == -1) {
                    bpos += dirp->d_reclen;
                    continue;
                }

                if (checkTracerPid(statusFd)) {
                    SecureAPI::close(statusFd);
                    SecureAPI::close(fd);
                    return true;
                }

                SecureAPI::close(statusFd);
            }
            bpos += dirp->d_reclen;
        }
    }

    SecureAPI::close(fd);
    return false;
}

bool AntiDebug::checkTracerPid(int fd) {
    char buf[512];
    while (readLine(fd, buf, sizeof(buf)) > 0) {
        if (SecureAPI::strncmp(buf, "TracerPid:", 10) == 0) {
            int pid = atoi(buf + 10);
            LOGI("AntiDebug::checkTracerPid(%d) pid: %d", fd, pid);
            if (pid != 0) {
                if (this->onDebuggerDetected) {
                    time_t now = time(0);
                    if (std::find(this->m_debug_times.begin(), this->m_debug_times.end(), now) == this->m_debug_times.end()) {
                        this->m_debug_times.push_back(now);
                        this->onDebuggerDetected();
                    }
                }
                return true;
            }
        }
    }
    return false;
}

size_t AntiDebug::readLine(int fd, char *buf, size_t bufSize) {
    size_t i = 0, n;
    char c;
    while (i < bufSize - 1) {
        n = SecureAPI::read(fd, &c, 1);
        if (n == -1) {
            return -1;
        }

        if (n == 0 || c == '\n') {
            break;
        }

        buf[i++] = c;
    }
    buf[i] = '\0';

    return i;
}