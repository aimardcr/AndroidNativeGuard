#include <stdio.h>
#include <unistd.h>

#include <android/log.h>
#include <string>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "NativeGuard", __VA_ARGS__)) // Disable this on production
