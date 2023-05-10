#include "../IModule.h"

class AntiDump : public IModule {
public:
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
};