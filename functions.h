#pragma once

#include <windows.h>
#include <iostream>
#include <unordered_set>

#ifndef FUNCTIONS_H
#define FUNCTIONS_H
std::string HTTPGetRequest(LPCWSTR httpUrl, LPCWSTR httpUri);
BOOL isElevated();
std::string resolveDriverPath(char* driverPath);
std::unordered_set<std::string> buildHashSet(const std::string jsonData);
std::string getSHA256(std::string filePath);
void readVector(std::vector<std::string> list);
BOOL verifyDriverSignatureEmbedded(std::string driverFile);
BOOL verifyDriverSignatureCatalog(std::string driverFile);
void clearScreen();
void printHeader();
void enableANSI();
#endif