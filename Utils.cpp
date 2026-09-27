#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include "functions.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wintrust")

using json = nlohmann::json;
char versionNumber[] = "1.1";

static const char* const BOX_H  = "\xe2\x94\x80";
static const char* const BOX_V  = "\xe2\x94\x82";
static const char* const BOX_TL = "\xe2\x94\x8c";
static const char* const BOX_TR = "\xe2\x94\x90";
static const char* const BOX_BL = "\xe2\x94\x94";
static const char* const BOX_BR = "\xe2\x94\x98";
static const char* const CLR_RED    = "\033[91m";
static const char* const CLR_YELLOW = "\033[93m";
static const char* const CLR_RESET  = "\033[0m";

void enableANSI() {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE) return;

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode)) return;

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
#endif
}

void clearScreen() {
	std::cout << "\033[2J\033[1;1H";
}

void printHeader() {
	const int inner = 55;
	const int leftPad = 7;

	std::cout << "\n" << BOX_TL;
	for (int i = 0; i < inner; i++) std::cout << BOX_H;
	std::cout << BOX_TR << "\n";

	auto blankLine = [&]() {
		std::cout << BOX_V;
		for (int i = 0; i < inner; i++) std::cout << " ";
		std::cout << BOX_V << "\n";
	};

	auto contentLine = [&](const std::string& content, int visibleWidth) {
		std::cout << BOX_V;
		for (int i = 0; i < leftPad; i++) std::cout << " ";
		std::cout << content;
		int rightPad = inner - leftPad - visibleWidth;
		if (rightPad < 0) rightPad = 0;
		for (int i = 0; i < rightPad; i++) std::cout << " ";
		std::cout << BOX_V << "\n";
	};

	blankLine();

	const char* art[8] = {
"  _____                    _       _     _   ",
" |  __ \\                  (_)     | |   | |  ",
" | |__) | __ ___ _   _ ___ _  __ _| |__ | |_ ",
" |  ___/ '__/ _ \\ | | / __| |/ _` | '_ \\| __|",
" | |   | | |  __/ |_| \\__ \\ | (_| | | | | |_ ",
" |_|   |_|  \\___|\\__, |___/_|\\__, |_| |_|\\__|",
"                  __/ |       __/ |          ",
"                 |___/       |___/           "
	};
	for (int i = 0; i < 8; i++) {
		std::cout << BOX_V << "     " << CLR_RED << art[i] << CLR_RESET << "     " << BOX_V << "\n";
	}

	blankLine();

	std::string line1 = std::string("Device Driver Anomaly Scanner  \xc2\xb7  v") + versionNumber;
	int line1Visible = 35 + (int)(sizeof(versionNumber) - 1);
	contentLine(line1, line1Visible);
	contentLine("misthi0s (@_misthi0s)  \xc2\xb7  misthi0s.dev", 38);

	blankLine();

	std::cout << BOX_BL;
	for (int i = 0; i < inner; i++) std::cout << BOX_H;
	std::cout << BOX_BR << "\n";
}

std::string HTTPGetRequest(LPCWSTR httpUrl, LPCWSTR httpUri) {
	HINTERNET hSession, hConnect, hRequest;
	BOOL bResults;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	std::string responseData;

	hSession = WinHttpOpen(L"Preysight/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession) {
		hConnect = WinHttpConnect(hSession, httpUrl, INTERNET_DEFAULT_HTTPS_PORT, 0);
	}
	else {
		std::cout << "[-] Unable to start HTTP session. Error: " << GetLastError() << std::endl;
		return "";
	}

	if (hConnect) {
		hRequest = WinHttpOpenRequest(hConnect, L"GET", httpUri, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	} else {
		std::cout << "[-] Unable to connect to HTTP URL. Error: " << GetLastError() << std::endl;
		return "";
	}

	if (hRequest) {
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} else {
		std::cout << "[-] Unable to make HTTP GET Request. Error: " << GetLastError() << std::endl;
		return "";
	}

	if (bResults) {
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}
	else {
		std::cout << "[-] Unable to send HTTP request. Error: " << GetLastError() << std::endl;
		return "";
	}

	if (bResults) {
		do {
			dwSize = 0;
			if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
				std::vector<char> buffer(dwSize + 1, 0);
				if (WinHttpReadData(hRequest, (LPVOID)buffer.data(), dwSize, &dwDownloaded)) {
					responseData.append(buffer.data(), dwDownloaded);
				}
			}
		} while (dwSize > 0);
	}
	else {
		std::cout << "[-] Unable to retrieve data. Error: " << GetLastError() << std::endl;
		return "";
	}
	return responseData;
}

BOOL isElevated() {
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			if (Elevation.TokenIsElevated) {
				CloseHandle(hToken);
				return true;
			}
			else {
				CloseHandle(hToken);
				return false;
			}
		}
	}
	return false;
}

std::string resolveDriverPath(char* driverPath) {
	std::string pathStr(driverPath);
	if (pathStr.rfind("\\SystemRoot", 0) == 0) {
		char sysRoot[1024];
		GetEnvironmentVariable("SystemRoot", sysRoot, 1024);
		pathStr.replace(0, 11, sysRoot);
	}
	if (pathStr.rfind("\\??\\", 0) == 0) {
		pathStr.erase(0, 4);
	}
	return pathStr;
}

std::unordered_set<std::string> buildHashSet(const std::string jsonData)
{
	std::unordered_set<std::string> sha256_set;
	auto drivers = json::parse(jsonData);
	for (const auto& driver : drivers)
	{
		if (!driver.contains("KnownVulnerableSamples")) continue;
		for (const auto& sample : driver["KnownVulnerableSamples"])
		{
			if (!sample.contains("SHA256") || !sample["SHA256"].is_string()) continue;
			std::string hash = sample["SHA256"].get<std::string>();
			std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
			if (hash.empty() || hash == "NULL" || hash == "UNKNOWN") continue;
			sha256_set.insert(std::move(hash));
		}
	}
	return sha256_set;
}

std::string getSHA256(std::string filePath) {
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (mdctx == nullptr) {
		return "";
	}
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
		EVP_MD_CTX_free(mdctx);
		return "";
	}
	std::ifstream fp(filePath, std::ios::binary);
	if (!fp.is_open()) {
		EVP_MD_CTX_free(mdctx);
		return "";
	}

	char buffer[4096];
	while (fp.read(buffer, sizeof(buffer))) {
		EVP_DigestUpdate(mdctx, buffer, fp.gcount());
		}
	EVP_DigestUpdate(mdctx, buffer, fp.gcount());

	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hashLength = 0;
	EVP_DigestFinal_ex(mdctx, hash, &hashLength);

	EVP_MD_CTX_free(mdctx);

	std::stringstream ss;
	for (unsigned int i = 0; i < hashLength; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}

void printSummary(bool networkUsed,
	const std::vector<std::string>& vLolDrivers,
	const std::vector<std::string>& vTrust,
	const std::vector<std::string>& vExpiredCert,
	const std::vector<std::string>& vFilePath,
	const std::vector<std::string>& vFileExtension,
	const std::vector<std::string>& vFileExists,
	const std::vector<std::string>& vUnquotedPath) {

	struct Row { std::string label; size_t count; const char* color; };
	std::vector<Row> rows;
	if (networkUsed) rows.push_back({ "LOLDrivers", vLolDrivers.size(), CLR_RED });
	rows.push_back({ "Trust verification failed", vTrust.size(), CLR_RED });
	rows.push_back({ "Signing cert expired at signing time", vExpiredCert.size(), CLR_RED });
	rows.push_back({ "Abnormal file path", vFilePath.size(), CLR_YELLOW });
	rows.push_back({ "Abnormal file extension", vFileExtension.size(), CLR_YELLOW });
	rows.push_back({ "Nonexistent files", vFileExists.size(), CLR_YELLOW });
	rows.push_back({ "Unquoted service paths", vUnquotedPath.size(), CLR_YELLOW });

	const int inner = 45;
	const int leftPad = 2;
	const int rightPad = 2;
	const int countWidth = 4;
	const int labelZone = inner - leftPad - rightPad - countWidth; // 37

	std::string topLabel = " Summary ";
	std::cout << "\n" << BOX_TL << BOX_H << topLabel;
	int topUsed = 1 + (int)topLabel.size();
	for (int i = 0; i < inner - topUsed; i++) std::cout << BOX_H;
	std::cout << BOX_TR << "\n";

	for (const auto& row : rows) {
		std::string label = row.label + " ";
		while ((int)label.size() < labelZone) label += ".";
		if ((int)label.size() > labelZone) label = label.substr(0, labelZone);

		std::string countStr = std::to_string(row.count);
		while ((int)countStr.size() < countWidth) countStr = " " + countStr;

		std::cout << BOX_V << "  " << label;
		if (row.count > 0) std::cout << row.color << countStr << CLR_RESET;
		else std::cout << countStr;
		std::cout << "  " << BOX_V << "\n";
	}

	std::cout << BOX_BL;
	for (int i = 0; i < inner; i++) std::cout << BOX_H;
	std::cout << BOX_BR << "\n";
}

void printSection(const std::string& title,
	const std::vector<std::string>& items,
	const std::string& glyph,
	const char* color) {
	if (items.empty()) return;

	const int totalWidth = 47;
	int used = 2 + 1 + (int)title.size() + 1;
	std::cout << "\n" << BOX_H << BOX_H << " " << title << " ";
	for (int i = 0; i < totalWidth - used; i++) std::cout << BOX_H;
	std::cout << "\n";

	for (const auto& item : items) {
		std::cout << "  " << color << glyph << CLR_RESET << "  " << item << "\n";
	}
}

static BOOL walkSignerAndCheckExpiry(HANDLE hWVTStateData, BOOL* pDetermined) {
	*pDetermined = FALSE;
	if (!hWVTStateData) return FALSE;
	CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(hWVTStateData);
	if (!pProvData) return FALSE;
	CRYPT_PROVIDER_SGNR* pSgnr = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
	if (!pSgnr) return FALSE;
	CRYPT_PROVIDER_CERT* pCert = WTHelperGetProvCertFromChain(pSgnr, 0);
	if (!pCert || !pCert->pCert || !pCert->pCert->pCertInfo) return FALSE;
	*pDetermined = TRUE;
	return CompareFileTime(&pCert->pCert->pCertInfo->NotAfter, &pSgnr->sftVerifyAsOf) < 0 ? TRUE : FALSE;
}

DriverSigInfo verifyDriverSignatureEmbedded(std::string driverFile) {
	DriverSigInfo info = { FALSE, FALSE, FALSE };
	std::wstring wDriverFile = std::wstring(driverFile.begin(), driverFile.end());
	LPCWSTR wdFile = wDriverFile.c_str();

	WINTRUST_FILE_INFO fileData = { sizeof(WINTRUST_FILE_INFO) };
	fileData.pcwszFilePath = wdFile;

	WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pFile = &fileData;

	GUID pgActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG lStatus = WinVerifyTrust(NULL, &pgActionId, &winTrustData);

	info.trusted = (lStatus == ERROR_SUCCESS) ? TRUE : FALSE;
	info.certExpired = walkSignerAndCheckExpiry(winTrustData.hWVTStateData, &info.certChecked);

	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &pgActionId, &winTrustData);

	return info;
}

DriverSigInfo verifyDriverSignatureCatalog(std::string driverFile) {
	DriverSigInfo info = { FALSE, FALSE, FALSE };
	std::wstring wDriverFile = std::wstring(driverFile.begin(), driverFile.end());
	LPCWSTR wdFile = wDriverFile.c_str();

	HANDLE hFile = CreateFileW(wdFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return info;
	}

	HCATADMIN hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
		CloseHandle(hFile);
		return info;
	}

	DWORD cbHash = 0;
	CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, NULL, 0);
	BYTE* pbHash = (BYTE*)LocalAlloc(0, cbHash);
	if (!pbHash) {
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		CloseHandle(hFile);
		return info;
	}
	CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, pbHash, 0);

	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, 0, NULL);
	if (hCatInfo) {
		CATALOG_INFO catInfo = { sizeof(CATALOG_INFO) };
		CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0);

		WINTRUST_CATALOG_INFO wtCatInfo = { sizeof(WINTRUST_CATALOG_INFO) };
		wtCatInfo.pcwszCatalogFilePath = catInfo.wszCatalogFile;
		wtCatInfo.pbCalculatedFileHash = pbHash;
		wtCatInfo.cbCalculatedFileHash = cbHash;

		WINTRUST_DATA winTrustData = { sizeof(WINTRUST_DATA) };
		winTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
		winTrustData.pCatalog = &wtCatInfo;
		winTrustData.dwUIChoice = WTD_UI_NONE;
		winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

		GUID pgActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		LONG lStatus = WinVerifyTrust(NULL, &pgActionId, &winTrustData);

		info.trusted = (lStatus == ERROR_SUCCESS) ? TRUE : FALSE;
		info.certExpired = walkSignerAndCheckExpiry(winTrustData.hWVTStateData, &info.certChecked);

		winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &pgActionId, &winTrustData);

		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
	}

	LocalFree(pbHash);
	CryptCATAdminReleaseContext(hCatAdmin, 0);
	CloseHandle(hFile);

	return info;
}

BOOL writeJsonReport(const std::string& outputPath,
	bool networkUsed,
	const std::vector<std::string>& vFileExists,
	const std::vector<std::string>& vFileExtension,
	const std::vector<std::string>& vFilePath,
	const std::vector<std::string>& vTrust,
	const std::vector<std::string>& vExpiredCert,
	const std::vector<std::string>& vLolDrivers,
	const std::vector<std::string>& vUnquotedPath) {
	SYSTEMTIME st;
	GetSystemTime(&st);
	char timestamp[32];
	std::snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02uZ",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	char host[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD hostLen = sizeof(host) / sizeof(host[0]);
	if (!GetComputerNameA(host, &hostLen)) {
		host[0] = '\0';
	}

	json report;
	report["scan"] = {
		{ "tool", "Preysight" },
		{ "version", versionNumber },
		{ "timestamp_utc", timestamp },
		{ "host", host },
		{ "network", networkUsed }
	};
	report["results"] = {
		{ "nonexistent_files", vFileExists },
		{ "abnormal_extension", vFileExtension },
		{ "abnormal_path", vFilePath },
		{ "trust_failed", vTrust },
		{ "expired_cert", vExpiredCert },
		{ "unquoted_path", vUnquotedPath }
	};
	if (networkUsed) {
		report["results"]["loldrivers"] = vLolDrivers;
	}

	std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
	if (!out.is_open()) {
		return FALSE;
	}
	out << report.dump(2);
	if (!out.good()) {
		return FALSE;
	}
	return TRUE;
}