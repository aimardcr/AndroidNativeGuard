#include "../IModule.h"

class RootDetect : public IModule {
public:
    const char *getName() override;
    eModuleSeverity getSeverity() override;

    bool execute() override;
private:
    bool detectSuBinaries();
    bool detectMagiskMount();

    size_t readLine(int fd, char *buf, size_t bufSize);
};