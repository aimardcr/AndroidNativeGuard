#ifndef IMODULE
#define IMODULE
#include <stdio.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <map>
#include <algorithm>

enum eSeverity {
    HIGH, // Dangerous and might harm the application's integrity
    MEDIUM, // Not so dangerous but can be used to harm the application's integrity
    LOW // Common security issue and might not harm the application's integrity
};

class IModule {
public:
    virtual const char *getName() = 0;
    virtual eSeverity getSeverity() = 0;

    virtual bool execute() = 0;
};
#endif