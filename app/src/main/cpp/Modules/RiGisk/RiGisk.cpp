#include "RiGisk.h"
#include "SecureAPI.h"
#include "Log.h"

#include "ElfImg.h"

#include <vector>
#include <fcntl.h>
#include <dirent.h>

struct soinfo {
#ifdef __LP64__
    inline static size_t solist_next_offset = 0x30;
    constexpr static size_t solist_realpath_offset = 0x1a8;
#else
    inline static size_t solist_next_offset = 0xa4;
    constexpr static size_t solist_realpath_offset = 0x174;
#endif

    inline static const char *(*get_realpath_sym)(soinfo *) = nullptr;
    inline static const char *(*get_soname_sym)(soinfo *) = nullptr;

    soinfo *next() {
        return *(soinfo **) ((uintptr_t) this + solist_next_offset);
    }

    const char *get_realpath() {
        return get_realpath_sym ? get_realpath_sym(this) :
               ((std::string *) ((uintptr_t) this + solist_realpath_offset))->c_str();
    }

    const char *get_soname() {
        return get_soname_sym ? get_soname_sym(this) :
               *((const char **) ((uintptr_t) this + solist_realpath_offset - sizeof(void *)));
    }
};

soinfo *solist = nullptr;
soinfo *somain = nullptr;
std::vector<soinfo *> *preloads = nullptr;

template<typename T> inline T *getStaticPointer(const SandHook::ElfImg &linker, std::string_view name) {
    auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name.data()));
    return addr == nullptr ? nullptr : *addr;
}

const char *RiGisk::getName() {
    return "Riru & Zygisk Detection";
}

eSeverity RiGisk::getSeverity() {
    return MEDIUM;
}

bool RiGisk::execute() {
    LOGI("RiGisk::execute");

    SandHook::ElfImg linker("/linker");
    solist = getStaticPointer<soinfo>(linker, "__dl__ZL6solist");
    somain = getStaticPointer<soinfo>(linker, "__dl__ZL6somain");
    preloads = reinterpret_cast<std::vector<soinfo *> *>(linker.getSymbAddress("__dl__ZL13g_ld_preloads"));
    LOGI("RiGisk::execute solist: %p, somain: %p, preloads: %p", solist, somain, preloads);

    soinfo::get_realpath_sym = reinterpret_cast<decltype(soinfo::get_realpath_sym)>(linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
    soinfo::get_soname_sym = reinterpret_cast<decltype(soinfo::get_soname_sym)>(linker.getSymbAddress("__dl__ZNK6soinfo10get_sonameEv"));
    LOGI("RiGisk::execute get_realpath_sym: %p, get_soname_sym: %p", soinfo::get_realpath_sym, soinfo::get_soname_sym);

    auto vsdo = getStaticPointer<soinfo>(linker, "__dl__ZL4vdso");
    LOGI("RiGisk::execute vsdo: %p", vsdo);
    for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
        auto *possible_next = *(void **) ((uintptr_t) solist + i * sizeof(void *));
        if (possible_next == somain || (vsdo != nullptr && possible_next == vsdo)) {
            soinfo::solist_next_offset = i * sizeof(void *);
            LOGI("RiGisk::execute solist_next_offset: %zu", soinfo::solist_next_offset);
            break;
        }
    }

    if (somain) {
        for (auto *iter = somain; iter; iter = iter->next()) {
            LOGI("RiGisk::execute somain so: %p, realpath: %s, soname: %s", iter, iter->get_realpath(), iter->get_soname());
            if (iter->get_realpath() && iter->get_soname()) {
                if (SecureAPI::strstr(iter->get_realpath(), "riru")) {
                    LOGI("RiGisk::execute riru detected");
                    return true;
                } else if (SecureAPI::strstr(iter->get_soname(), "riru")) {
                    LOGI("RiGisk::execute riru detected");
                    return true;
                }
            }
        }
    }

    if (solist) {
        for (auto *iter = solist; iter; iter = iter->next()) {
            LOGI("RiGisk::execute solist so: %p, realpath: %s, soname: %s", iter, iter->get_realpath(), iter->get_soname());
            if (iter->get_realpath() && iter->get_soname()) {
                if (SecureAPI::strstr(iter->get_realpath(), "riru")) {
                    LOGI("RiGisk::execute riru detected");
                    return true;
                } else if (SecureAPI::strstr(iter->get_soname(), "riru")) {
                    LOGI("RiGisk::execute riru detected");
                    return true;
                }
            }
        }
    }

    if (preloads) {
        for (auto so: *preloads) {
            LOGI("RiGisk::execute preloads so: %p, realpath: %s, soname: %s", so, so->get_realpath(), so->get_soname());
            if (so->get_realpath() && so->get_soname()) {
                if (SecureAPI::strstr(so->get_realpath(), "zygisk")) {
                    LOGI("RiGisk::execute zygisk detected");
                    return true;
                } else if (SecureAPI::strstr(so->get_soname(), "zygisk")) {
                    LOGI("RiGisk::execute zygisk detected");
                    return true;
                }
            }
        }
    }

    return false;
}