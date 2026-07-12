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

void enableANSI() {
#ifdef _WIN32
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
	std::cout << "\n\t\tDriver Checker" << std::endl;
	std::cout << "\t\tVersion: 0.1" << std::endl;
	std::cout << "\t\tAuthor: misthi0s (@_misthi0s)" << std::endl;
	std::cout << "\t\t\thttps://misthi0s.dev" << std::endl;
}

std::string HTTPGetRequest(LPCWSTR httpUrl, LPCWSTR httpUri) {
	HINTERNET hSession, hConnect, hRequest;
	BOOL bResults;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	std::string responseData;

	hSession = WinHttpOpen(L"DriverChecker/1.0",
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

void readVector(std::vector<std::string> list) {
	for (const auto& item : list) {
		std::cout << "\t" << item << std::endl;
	}
}

BOOL verifyDriverSignatureEmbedded(std::string driverFile) {
	std::wstring wDriverFile = std::wstring(driverFile.begin(), driverFile.end());
	LPCWSTR wdFile = wDriverFile.c_str();

	WINTRUST_FILE_INFO fileData;
	memset(&fileData, 0, sizeof(fileData));
	fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileData.pcwszFilePath = wdFile;
	fileData.hFile = NULL;
	fileData.pgKnownSubject = NULL;

	WINTRUST_DATA winTrustData;
	memset(&winTrustData, 0, sizeof(winTrustData));
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.pPolicyCallbackData = NULL;
	winTrustData.pSIPClientData = NULL;
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.hWVTStateData = NULL;
	winTrustData.pFile = &fileData;

	GUID pgActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG lStatus = WinVerifyTrust(NULL, &pgActionId, &winTrustData);

	if (lStatus == 0) {
		return true;
	}
	else {
		return false;
	}
}

BOOL verifyDriverSignatureCatalog(std::string driverFile) {
	std::wstring wDriverFile = std::wstring(driverFile.begin(), driverFile.end());
	LPCWSTR wdFile = wDriverFile.c_str();

	HANDLE hFile = CreateFileW(wdFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}
	HCATADMIN hCatAdmin;
	DWORD cbHash = 0;
	CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0);
	CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, NULL, 0);

	BYTE* pbHash = (BYTE*)LocalAlloc(0, cbHash);
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

		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
		LocalFree(pbHash);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		CloseHandle(hFile);

		if (lStatus == 0) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		return false;
	}
}