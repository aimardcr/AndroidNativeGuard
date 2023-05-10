#include "../IModule.h"

class RiGisk : public IModule {
public:
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    bool detectRiru();
    bool detectZygisk();

    size_t readLine(int fd, char *buf, size_t bufSize);
};