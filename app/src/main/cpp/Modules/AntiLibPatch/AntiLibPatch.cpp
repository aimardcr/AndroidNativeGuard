#include "AntiLibPatch.h"
#include "SecureAPI.h"
#include "Log.h"

#include <vector>
#include <map>

#include <elf.h>
#include <fcntl.h>
#include <dirent.h>
#include <link.h>
#include <dlfcn.h>

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#endif

static std::vector<std::string> blacklists {
    // Add your library here incase you don't want a certain library to be detected when it's tampered
};

__attribute__((always_inline)) static inline uint32_t crc32(uint8_t *data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (size_t j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

__attribute__((always_inline)) static inline const char *get_filename(const char *path) {
    for (const char *s = path; *s; s++) {
        if (*s == '/') {
            path = s + 1;
        }
    }
    return path;
}

AntiLibPatch::AntiLibPatch(void (*callback)(const char *name, const char *section, uint32_t old_checksum, uint32_t new_checksum)) : onLibTampered(callback) {
    LOGI("AntiLibPatch::AntiLibPatch");

    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        if (!strstr(info->dlpi_name, ".so")) {
            return 0;
        }

        LOGI("AntiLibPatch::AntiLibPatch info->dlpi_name: %s", info->dlpi_name);
        int fd = SecureAPI::openat(AT_FDCWD, info->dlpi_name, O_RDONLY, 0);
        if (fd == -1) {
            return 0;
        }

        Elf_Ehdr ehdr;
        SecureAPI::read(fd, &ehdr, sizeof(Elf_Ehdr));

        Elf_Shdr shdr;
        SecureAPI::lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf_Shdr), SEEK_SET);
        SecureAPI::read(fd, &shdr, sizeof(Elf_Shdr));

        char *shstrtab = new char[shdr.sh_size];
        SecureAPI::lseek(fd, shdr.sh_offset, SEEK_SET);
        SecureAPI::read(fd, shstrtab, shdr.sh_size);

        SecureAPI::lseek(fd, ehdr.e_shoff, SEEK_SET);
        for (int i = 0; i < ehdr.e_shnum; i++) {
            SecureAPI::read(fd, &shdr, sizeof(Elf_Shdr));
            const char *name = shstrtab + shdr.sh_name;

            if (shdr.sh_type == SHT_PROGBITS) {
                if ((shdr.sh_flags & (SHF_EXECINSTR | SHF_ALLOC)) == (SHF_EXECINSTR | SHF_ALLOC)) {
                    char *tmp = new char[shdr.sh_size];
                    SecureAPI::lseek(fd, shdr.sh_addr, SEEK_SET);
                    SecureAPI::read(fd, tmp, shdr.sh_size);

                    uint32_t checksum = ((std::map<std::string, std::map<std::string, uint32_t>> *) data)->operator[](info->dlpi_name)[name] = crc32((uint8_t *) tmp, shdr.sh_size);
                    LOGI("AntiLibPatch::AntiLibPatch this->m_checksums[%s][%s]: 0x%08X", info->dlpi_name, name, checksum);
                    delete[] tmp;
                }
            }
        }

        free(shstrtab);
        SecureAPI::close(fd);
        return 0;
    }, &this->m_checksums);
}

const char *AntiLibPatch::getName() {
    return "Lib. Patch & Hook Detection";
}

eSeverity AntiLibPatch::getSeverity() {
    return HIGH;
}

bool AntiLibPatch::execute() {
    LOGI("AntiLibPatch::execute");

    std::vector<dl_phdr_info> infos;
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        ((std::vector<dl_phdr_info> *) data)->push_back(*info);
        return 0;
    }, &infos);

    for (auto info : infos) {
        if (!strstr(info.dlpi_name, ".so") || this->m_checksums.count(info.dlpi_name) == 0 || std::find(blacklists.begin(), blacklists.end(), get_filename(info.dlpi_name)) != blacklists.end()) {
            continue;
        }

        LOGI("AntiLibPatch::execute info.dlpi_name: %s", info.dlpi_name);
        int fd = SecureAPI::openat(AT_FDCWD, info.dlpi_name, O_RDONLY, 0);
        if (fd == -1) {
            continue;
        }

        Elf_Ehdr ehdr;
        SecureAPI::read(fd, &ehdr, sizeof(Elf_Ehdr));

        Elf_Shdr shdr;
        SecureAPI::lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf_Shdr), SEEK_SET);
        SecureAPI::read(fd, &shdr, sizeof(Elf_Shdr));

        char *shstrtab = new char[shdr.sh_size];
        SecureAPI::lseek(fd, shdr.sh_offset, SEEK_SET);
        SecureAPI::read(fd, shstrtab, shdr.sh_size);

        SecureAPI::lseek(fd, ehdr.e_shoff, SEEK_SET);
        for (int i = 0; i < ehdr.e_shnum; i++) {
            SecureAPI::read(fd, &shdr, sizeof(Elf_Shdr));
            const char *name = shstrtab + shdr.sh_name;

            if (shdr.sh_type == SHT_PROGBITS) {
                if ((shdr.sh_flags & (SHF_EXECINSTR | SHF_ALLOC)) == (SHF_EXECINSTR | SHF_ALLOC)) {
                    if (!SecureAPI::strcmp(name, ".plt")) {
                        continue;
                    }

                    uint32_t checksum = crc32((uint8_t *) info.dlpi_addr + shdr.sh_addr, shdr.sh_size);
                    LOGI("AntiLibPatch::execute %s[%s] checksum: 0x%08X -> 0x%08X", info.dlpi_name, name, this->m_checksums[info.dlpi_name][name], checksum);
                    if (this->m_checksums[info.dlpi_name][name] != checksum) {
                        LOGI("AntiLibPatch::execute %s[%s] checksum mismatch", info.dlpi_name, name);
                        if (this->onLibTampered) {
                            if (this->m_last_checksums.find(info.dlpi_name) == this->m_last_checksums.end() || this->m_last_checksums[info.dlpi_name][name] != checksum) {
                                this->m_last_checksums[info.dlpi_name][name] = checksum;
                                this->onLibTampered(info.dlpi_name, name, this->m_checksums[info.dlpi_name][name], checksum);
                            }
                        }
                        return true;
                    }
                }
            }
        }

        free(shstrtab);
        SecureAPI::close(fd);
    }
    return false;
}