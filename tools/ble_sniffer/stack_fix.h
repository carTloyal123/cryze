// stack_fix.h - Override Arduino loop task stack size for ESP32-C6
// WiFi library needs >16KB stack on C6!
#pragma once
size_t getArduinoLoopTaskStackSize(void) { return 32768; }
