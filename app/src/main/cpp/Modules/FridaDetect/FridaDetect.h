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

    std::vector<time_t> m_frida_times;
    void (*onFridaDetected)();
};