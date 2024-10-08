#include "../IModule.h"

class AntiDump : public IModule {
public:
    AntiDump(void (*)() = 0);
    const char *getName() override;
    eSeverity getSeverity() override;

    bool execute() override;
private:
    int m_fd = -1;
    int m_wd[100];
    int m_count = 0;

    std::vector<time_t> m_dump_times;
    void (*onDumpDetected)();
};