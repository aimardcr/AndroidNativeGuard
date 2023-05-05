#include <stdio.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include <jni.h>

#include "AntiDebug/AntiDebug.h"
#include "FridaDetect/FridaDetect.h"
#include "RiGisk/RiGisk.h"
#include "RootDetect/RootDetect.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_id_kuro_androidnativeguard_MainActivity_getResult(JNIEnv *env, jobject thiz) {
    std::string result;

    std::vector<IModule *> modules {
        new AntiDebug(),
        new FridaDetect(),
        new RiGisk(),
        new RootDetect()
    };

    for (auto module : modules) {
        result += "<div>";
        result += module->getName();
        result += ": ";
        if (module->execute()) {
            result += "<span style='color: red'>Failed</span>";
        } else {
            result += "<span style='color: green'>Passed</span>";
        }
        result += "</div>";
    }

    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {

    return JNI_VERSION_1_6;
}