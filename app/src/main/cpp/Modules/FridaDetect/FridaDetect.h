#include "../IModule.h"

class FridaDetect : public IModule {
public:
    const char *getName() override;
    eModuleSeverity getSeverity() override;

    bool execute() override;
private:
    bool detectFridaAgent();
    bool detectFridaPipe();

    size_t readLine(int fd, char *buf, size_t bufSize);
};