#include "../IModule.h"

class AntiLibPatch : public IModule {
private:
    std::map<std::string, std::map<std::string, uint32_t>> m_checksums;
public:
    AntiLibPatch();
    const char *getName() override;
    eModuleSeverity getSeverity() override;

    bool execute() override;
};