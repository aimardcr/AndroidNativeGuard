#include "../IModule.h"

class FridaDetect : public IModule {
public:
    FridaDetect(void (*)());
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    bool detectFridaAgent();
    bool detectFridaPipe();
    bool detectFridaListener();

    size_t readLine(int fd, char *buf, size_t bufSize);

    std::vector<time_t> m_frida_times;
    void (*onFridaDetected)();
};