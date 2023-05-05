#include "../IModule.h"

class AntiDump : public IModule {
public:
    const char *getName() override;
    eModuleSeverity getSeverity() override;

    bool execute() override;
};