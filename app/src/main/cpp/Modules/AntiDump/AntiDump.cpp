#include "AntiDump.h"
#include "SecureAPI.h"
#include "Log.h"

#include <sys/inotify.h>
#include <sys/select.h>
#include <fcntl.h>
#include <dirent.h>

AntiDump::AntiDump(void (*callback)()) : onDumpDetected(callback) {

}

const char *AntiDump::getName() {
    return "Memory Dump Detection";
}

eSeverity AntiDump::getSeverity() {
    return MEDIUM;
}

bool AntiDump::execute() {
    int fd = SecureAPI::inotify_init1(0);
    if (fd < 0) {
        LOGI("AntiDump::execute inotify_init1 failed");
        if (errno == EMFILE || errno == ENFILE) {
            LOGI("AntiDump::execute inotify_init1 probably failed because of max_user_watches being tampered.");
        }
        return true;
    }

    int n = 0;
    int wd[100];

    wd[n++] = SecureAPI::inotify_add_watch(fd, "/proc/self/maps", IN_ACCESS | IN_OPEN);
    wd[n++] = SecureAPI::inotify_add_watch(fd, "/proc/self/mem", IN_ACCESS | IN_OPEN);
    wd[n++] = SecureAPI::inotify_add_watch(fd, "/proc/self/pagemap", IN_ACCESS | IN_OPEN);

    struct linux_dirent64 *dirp;
    char buf[512];
    int nread;

    int task = SecureAPI::openat(AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY, 0);
    while ((nread = SecureAPI::getdents64(task, (struct linux_dirent64 *) buf, sizeof(buf))) > 0) {
        for (int bpos = 0; bpos < nread;) {
            dirp = (struct linux_dirent64 *) (buf + bpos);
            if (!SecureAPI::strcmp(dirp->d_name, ".") || !SecureAPI::strcmp(dirp->d_name, "..") ) {
                bpos += dirp->d_reclen;
                continue;
            }
            if (dirp->d_type == DT_DIR) {
                char memPath[512], pagemapPath[512];
                sprintf(memPath, "/proc/self/task/%s/mem", dirp->d_name);
                sprintf(pagemapPath, "/proc/self/task/%s/pagemap", dirp->d_name);

                wd[n++] = SecureAPI::inotify_add_watch(fd, memPath, IN_ACCESS | IN_OPEN);
                wd[n++] = SecureAPI::inotify_add_watch(fd, pagemapPath, IN_ACCESS | IN_OPEN);
            }
            bpos += dirp->d_reclen;
        }
    }
    SecureAPI::close(task);

    int len = (int) SecureAPI::read(fd, buf, sizeof(buf));
    if (len > 0) {
        LOGI("AntiDump::execute len: %d", len);
        struct inotify_event *event;
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (struct inotify_event *) ptr;
            if (event->mask & IN_ACCESS || event->mask & IN_OPEN) {
                LOGI("AntiDump::execute event->mask: %d", event->mask);
                SecureAPI::close(fd);

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

    for (int i = 0; i < n; i++) {
        if (wd[i]) {
            SecureAPI::inotify_rm_watch(fd, wd[i]);
        }
    }

    SecureAPI::close(fd);
    return false;
}