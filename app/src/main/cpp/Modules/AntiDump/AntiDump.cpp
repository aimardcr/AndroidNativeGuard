#include "AntiDump.h"
#include "SecureAPI.h"
#include "Log.h"
#include "obfuscate.h"

#include <sys/inotify.h>
#include <sys/select.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

AntiDump::AntiDump(void (*callback)()) : onDumpDetected(callback) {
    this->m_fd = SecureAPI::inotify_init1(0);
    if (this->m_fd == -1) {
        LOGI("AntiDump::execute inotify_init1 failed");
        if (errno == EMFILE || errno == ENFILE) {
            LOGI("AntiDump::execute inotify_init1 probably failed because of max_user_watches being tampered.");
        }
        return;
    }

    this->m_wd[this->m_count++] = SecureAPI::inotify_add_watch(this->m_fd, AY_OBFUSCATE("/proc/self/maps"), IN_ACCESS | IN_OPEN);
    this->m_wd[this->m_count++] = SecureAPI::inotify_add_watch(this->m_fd, AY_OBFUSCATE("/proc/self/mem"), IN_ACCESS | IN_OPEN);
    this->m_wd[this->m_count++] = SecureAPI::inotify_add_watch(this->m_fd, AY_OBFUSCATE("/proc/self/pagemap"), IN_ACCESS | IN_OPEN);

    struct linux_dirent64 *dirp;
    char buf[512];
    int nread;

    int task = SecureAPI::openat(AT_FDCWD, AY_OBFUSCATE("/proc/self/task"), O_RDONLY | O_DIRECTORY, 0);
    while ((nread = SecureAPI::getdents64(task, (struct linux_dirent64 *) buf, sizeof(buf))) > 0) {
        for (int bpos = 0; bpos < nread;) {
            dirp = (struct linux_dirent64 *) (buf + bpos);
            if (!SecureAPI::strcmp(dirp->d_name, AY_OBFUSCATE(".")) ||
                !SecureAPI::strcmp(dirp->d_name, AY_OBFUSCATE(".."))) {
                bpos += dirp->d_reclen;
                continue;
            }
            if (dirp->d_type == DT_DIR) {
                char memPath[512], pagemapPath[512];
                sprintf(memPath, AY_OBFUSCATE("/proc/self/task/%s/mem").operator char *(), dirp->d_name);
                sprintf(pagemapPath, AY_OBFUSCATE("/proc/self/task/%s/pagemap").operator char *(), dirp->d_name);

                this->m_wd[this->m_count++] = SecureAPI::inotify_add_watch(this->m_fd, memPath, IN_ACCESS | IN_OPEN);
                this->m_wd[this->m_count++] = SecureAPI::inotify_add_watch(this->m_fd, pagemapPath, IN_ACCESS | IN_OPEN);
            }
            bpos += dirp->d_reclen;
        }
    }
    SecureAPI::close(task);
}

const char *AntiDump::getName() {
    return AY_OBFUSCATE("Memory Dump Detection");
}

eSeverity AntiDump::getSeverity() {
    return MEDIUM;
}

bool AntiDump::execute() {
    if (this->m_fd == -1) {
        return false;
    }

    char buf[4096];
    int len = (int) SecureAPI::read(this->m_fd, buf, sizeof(buf));
    if (len > 0) {
        LOGI("AntiDump::execute len: %d", len);
        struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (struct inotify_event *) ptr;
            if (event->mask & IN_ACCESS || event->mask & IN_OPEN) {
                LOGI("AntiDump::execute event->mask: %d", event->mask);
                SecureAPI::close(this->m_fd);

                if (this->onDumpDetected) {
                    time_t now = time(0);
                    if (std::find(this->m_dump_times.begin(), this->m_dump_times.end(), now) == this->m_dump_times.end()) {
                        this->m_dump_times.push_back(now);
                        this->onDumpDetected();
                    }
                }
                return true;
            }
        }
    }
    return false;
}