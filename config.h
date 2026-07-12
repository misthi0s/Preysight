#pragma once

#include <windows.h>
#include <vector>
#include <iostream>

#ifndef CONFIG_H
#define CONFIG_H
std::vector<std::string> suffixes = { ".sys", ".dll" };
std::vector<std::string> pathPatterns = { "\\system32\\", "\\program files" };

std::vector<std::string> fExtensionTuning = { "c:\\windows\\system32\\ntoskrnl.exe" };
std::vector<std::string> fExistsTuning = { "c:\\windows\\system32\\drivers\\dump_" };
#endif