#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include <thread>

#include <jni.h>

#include "Utils/Log.h"

#include "AntiDebug/AntiDebug.h"
#include "FridaDetect/FridaDetect.h"
#include "RiGisk/RiGisk.h"
#include "RootDetect/RootDetect.h"
#include "AntiDump/AntiDump.h"
#include "AntiLibPatch/AntiLibPatch.h"

JavaVM *g_VM;

jclass mainActivityClass;
jmethodID addLogMethod;
void addLog(std::string log) {
    JNIEnv *env;
    g_VM->AttachCurrentThread(&env, NULL);

    time_t now = time(0);
    tm *ltm = localtime(&now);

    char date[20];
    sprintf(date, "%02d:%02d:%02d", ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

    log = "[" + std::string(date) + "] " + log;

    env->CallStaticVoidMethod(mainActivityClass, addLogMethod, env->NewStringUTF(log.c_str()));

    g_VM->DetachCurrentThread();
}

// ==================== Callbacks ==================== //
void onDebuggerDetected() {
    addLog("<span style='color: green;'>AntiDebug</span>: <span style='color: red'>Debugger detected.</span>");
}

void onFridaDetected() {
    addLog("<span style='color: green;'>FridaDetect</span>: <span style='color: red'>Frida detected.</span>");
}

void onDumpDetected() {
    addLog("<span style='color: green;'>AntiDump</span>: <span style='color: red'>An attempt to access/dump memory detected.</span>");
}

void onLibTampered(const char *name, const char *section, uint32_t old_checksum, uint32_t new_checksum) {
    char log[1024];
    sprintf(log, "<span style='color: green;'>AntiLibPatch</span>: <span style='color: red'>%s</span> %s has been tampered, 0x%08X -> 0x%08X", name, section, old_checksum, new_checksum);
    addLog(log);
}

// ==================== Main ==================== //
std::vector<IModule *> services;
std::vector<std::thread> threads;

void AndroidNativeGuard() {
    addLog("<span style='color: yellow;'>Android Native Guard</span> service started.");

    RootDetect rootDetect;
    if (rootDetect.execute()) {
        addLog("<span style='color: green;'>RootDetect</span>: <span style='color: red'>Root detected.</span>");
    }

    RiGisk riGisk;
    if (riGisk.execute()) {
        addLog("<span style='color: green;'>RiGisk</span>: <span style='color: red'>Zygote injection detected.</span>");
    }

    services.push_back(new AntiDebug(onDebuggerDetected));
    services.push_back(new FridaDetect(onFridaDetected));
    services.push_back(new AntiDump(onDumpDetected));
    services.push_back(new AntiLibPatch(onLibTampered));

    for (auto &service : services) {
        threads.emplace_back([&]() {
            while (true) {
                service->execute();
                sleep(1);
            }
        });
    }

    for (auto &thread : threads) {
        thread.detach();
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_VM = vm;

    JNIEnv *env;
    vm->GetEnv((void **)&env, JNI_VERSION_1_6);

    jclass clazz = env->FindClass("id/kuro/androidnativeguard/MainActivity");
    addLogMethod = env->GetStaticMethodID(clazz, "addLog", "(Ljava/lang/String;)V");
    mainActivityClass = (jclass)env->NewGlobalRef(clazz);

    AndroidNativeGuard();
    return JNI_VERSION_1_6;
}