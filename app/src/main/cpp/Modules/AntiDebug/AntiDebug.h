#include "../IModule.h"

class AntiDebug : public IModule {
public:
    const char *getName() override;
    eModuleSeverity getSeverity() override;

    bool execute() override;
private:
    bool scanStatus();
    bool scanTaskStatuses();

    bool checkTracerPid(int fd);
    size_t readLine(int fd, char *buf, size_t bufSize);
};