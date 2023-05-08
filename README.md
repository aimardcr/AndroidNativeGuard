# AndroidNativeGuard
All-in-one android application protection

# How secure is it?
Android Native Guard used what's called `Secure API` and low-level function call through inline `syscall` to prevent any bypass that could potentially break the security system.
Android Native Guard used various open-source projects to implement a true-secure android application system.

# Modules
- Debugger Detection
- Frida Detection
- Riru & Zygisk Detection
- Root Detection
- Memory Access & Dump Detection
- Library Patch & Hook Detection

# TODO
- Better documentation (codes & README)
- App Tamper Detection (signature, checksum, etc)
- Magisk-Hide Detection Module (e.g.: Shamiko)
- Blacklist lib. for AntiLibPatch module

# Notes
- Don't forget to add `android:extractNativeLibs="true"` to your `AndroidManifest.xml` so that module _AntiLibPatch_ can work properly.

# Credits
https://github.com/darvincisec/AntiDebugandMemoryDump

https://github.com/darvincisec/DetectFrida

https://github.com/aimardcr/NativeDetector
