#include "../IModule.h"

class FridaDetect : public IModule {
public:
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    bool detectFridaAgent();
    bool detectFridaPipe();
};