#pragma once

#include <windows.h>
#include <iostream>
#include <unordered_set>

#ifndef FUNCTIONS_H
#define FUNCTIONS_H
std::string HTTPGetRequest(LPCWSTR httpUrl, LPCWSTR httpUri);
BOOL isElevated();
int RegistryValueCheck();
ULONG CodeIntegrityCheck();
void printSystemConfigs(std::string ciEnabled, std::string testSigning, std::string hvciEnabled, std::string hvciStrict, std::string vulnDriverCheck);
std::string resolveDriverPath(char* driverPath);
std::unordered_set<std::string> buildHashSet(const std::string jsonData);
std::string getSHA256(std::string filePath);
void printSummary(bool networkUsed,
	const std::vector<std::string>& vLolDrivers,
	const std::vector<std::string>& vTrust,
	const std::vector<std::string>& vExpiredCert,
	const std::vector<std::string>& vFilePath,
	const std::vector<std::string>& vFileExtension,
	const std::vector<std::string>& vFileExists);
void printSection(const std::string& title,
	const std::vector<std::string>& items,
	const std::string& glyph,
	const char* color);
struct DriverSigInfo {
	BOOL trusted;
	BOOL certChecked;
	BOOL certExpired;
};
DriverSigInfo verifyDriverSignatureEmbedded(std::string driverFile);
DriverSigInfo verifyDriverSignatureCatalog(std::string driverFile);
BOOL writeJsonReport(const std::string& outputPath,
	bool networkUsed,
	const std::vector<std::string>& vFileExists,
	const std::vector<std::string>& vFileExtension,
	const std::vector<std::string>& vFilePath,
	const std::vector<std::string>& vTrust,
	const std::vector<std::string>& vExpiredCert,
	const std::vector<std::string>& vLolDrivers,
	std::string ciEnabled,
	std::string testSigning,
	std::string hvciEnabled,
	std::string hvciStrict,
	std::string vulnDriverCheck);
void clearScreen();
void printHeader();
void enableANSI();
#endif