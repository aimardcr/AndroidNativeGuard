#include "../IModule.h"

class AntiDump : public IModule {
public:
    AntiDump(void (*)() = 0);
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    std::vector<time_t> m_dump_times;
    void (*onDumpDetected)();
};