#include "FridaDetect.h"
#include "SecureAPI.h"
#include "Log.h"

#include <fcntl.h>
#include <dirent.h>

#include <link.h>
#include <dlfcn.h>

FridaDetect::FridaDetect(void (*callback)()) : onFridaDetected(callback) {

}

const char *FridaDetect::getName() {
    return "Frida Detection";
}

eSeverity FridaDetect::getSeverity() {
    return HIGH;
}

bool FridaDetect::execute() {
    LOGI("FridaDetect::execute");

    if (detectFridaAgent() || detectFridaPipe()) {
        if (this->onFridaDetected) {
            time_t now = time(0);
            if (std::find(this->m_frida_times.begin(), this->m_frida_times.end(), now) == this->m_frida_times.end()) {
                this->m_frida_times.push_back(now);
                this->onFridaDetected();
            }
        }
        return true;
    }
    return false;
}

bool FridaDetect::detectFridaAgent() {
    LOGI("FridaDetect::detectFridaAgent");

    bool result = false;
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        LOGI("FridaDetect::detectFridaAgent info->dlpi_name: %s", info->dlpi_name);
        if (SecureAPI::strstr(info->dlpi_name, "frida-agent") != nullptr) {
            LOGI("FridaDetect::detectFridaAgent found: %s", info->dlpi_name);
            *(bool *) data = true;
            return 1;
        }
        return 0;
    }, &result);
    return result;
}

bool FridaDetect::detectFridaPipe() {
    LOGI("FridaDetect::detectFridaPipe");
    int fd = SecureAPI::openat(AT_FDCWD, "/proc/self/fd", O_RDONLY | O_DIRECTORY, 0);
    if (fd == -1) {
        return true;
    }
    LOGI("FridaDetect::detectFridaPipe fd: %d", fd);

    struct linux_dirent64 *dirp;
    char buf[512];
    int nread;

    while ((nread = SecureAPI::getdents64(fd, (struct linux_dirent64 *) buf, sizeof(buf))) > 0) {
        for (int bpos = 0; bpos < nread;) {
            dirp = (struct linux_dirent64 *) (buf + bpos);
            if (dirp->d_type == DT_LNK) {
                LOGI("FridaDetect::detectFridaPipe dirp->d_name: %s", dirp->d_name);
                if (!SecureAPI::strcmp(dirp->d_name, ".") || !SecureAPI::strcmp(dirp->d_name, "..")) {
                    bpos += dirp->d_reclen;
                    continue;
                }

                char linkPath[512];
                sprintf(linkPath, "/proc/self/fd/%s", dirp->d_name);
                char linkTarget[512];
                int linkTargetLen = SecureAPI::readlinkat(fd, dirp->d_name, linkTarget, sizeof(linkTarget));
                if (linkTargetLen == -1) {
                    SecureAPI::close(fd);
                    return true;
                }
                linkTarget[linkTargetLen] = '\0';
                LOGI("FridaDetect::detectFridaPipe linkPath: %s | linkTarget: %s", linkPath, linkTarget);

                if (SecureAPI::strstr(linkTarget, "linjector")) {
                    LOGI("FridaDetect::detectFridaPipe found: %s", linkTarget);
                    SecureAPI::close(fd);
                    return true;
                }
            }

            bpos += dirp->d_reclen;
        }
    }

    SecureAPI::close(fd);
    return false;
}