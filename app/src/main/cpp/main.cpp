#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <iostream>
#include <string>
#include <vector>
#include <time.h>

#include <jni.h>

#include "Utils/Log.h"

#include "AntiDebug/AntiDebug.h"
#include "FridaDetect/FridaDetect.h"
#include "RiGisk/RiGisk.h"
#include "RootDetect/RootDetect.h"
#include "AntiDump/AntiDump.h"

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

void *anti_dump_thread(void *) {
    addLog("<span style='color: green;'>AntiDump</span> service started.");

    AntiDump antiDump;
    while (1) {
        if (antiDump.execute()) {
            addLog("<span style='color: green;'>AntiDump</span>: <span style='color: red'>An attempt to access/dump memory detected.</span>");
        }
        sleep(1);
    }
    return 0;
}

void *main_thread(void *) {
    addLog("<span style='color: yellow;'>Android Native Guard</span> service started.");

    RootDetect rootDetect;
    if (rootDetect.execute()) {
        addLog("<span style='color: green;'>RootDetect</span>: <span style='color: red'>Root detected.</span>");
    }

    RiGisk riGisk;
    if (riGisk.execute()) {
        addLog("<span style='color: green;'>RiGisk</span>: <span style='color: red'>Zygote injection detected.</span>");
    }

    pthread_t t;
    pthread_create(&t, NULL, anti_dump_thread, NULL);

    while (1) {
        static bool antiDebugDetected = false; // Do not use this example in production since it's only to prevent spamming the log.
        if (!antiDebugDetected) {
            AntiDebug antiDebug;
            if (antiDebug.execute()) {
                addLog("<span style='color: green;'>AntiDebug</span>: <span style='color: red'>Anti-debugging detected.</span>");
                antiDebugDetected = true;
            }
        }

        static bool fridaDetected = false; // Do not use this example in production since it's only to prevent spamming the log.
        if (!fridaDetected) {
            FridaDetect fridaDetect;
            if (fridaDetect.execute()) {
                addLog("<span style='color: green;'>FridaDetect</span>: <span style='color: red'>Frida detected.</span>");
                fridaDetected = true;
            }
        }
        sleep(1);
    }
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_VM = vm;

    JNIEnv *env;
    vm->GetEnv((void **)&env, JNI_VERSION_1_6);

    jclass clazz = env->FindClass("id/kuro/androidnativeguard/MainActivity");
    addLogMethod = env->GetStaticMethodID(clazz, "addLog", "(Ljava/lang/String;)V");
    mainActivityClass = (jclass)env->NewGlobalRef(clazz);

    pthread_t t;
    pthread_create(&t, NULL, main_thread, NULL);
    return JNI_VERSION_1_6;
}