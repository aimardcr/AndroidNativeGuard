#include "../IModule.h"

class AntiLibPatch : public IModule {
private:
    std::map<std::string, std::map<std::string, uint32_t>> m_checksums;
public:
    AntiLibPatch(void (*)(const char *, const char *, uint32_t, uint32_t) = 0);
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    std::map<std::string, std::map<std::string, uint32_t>> m_last_checksums;
    void (*onLibTampered)(const char *name, const char *section, uint32_t old_checksum, uint32_t new_checksum);
};