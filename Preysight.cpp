#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <filesystem>
#include <vector>

#include "config.h"
#include "functions.h"

INT cFileExists(std::string filePath) {
    // INT Values
    // 0 - File exists on system
    // 1 - File does not exist on the system and is not tuned out
    // 2 - File does not exist on the system but is tuned out
    if (!(std::filesystem::exists(filePath))) {
        std::transform(filePath.begin(), filePath.end(), filePath.begin(), [](unsigned char c) {return std::tolower(c);  });
        bool match = std::any_of(fExistsTuning.begin(), fExistsTuning.end(), [&](const std::string& s) { return filePath.find(s) != std::string::npos; });
        if (!match) {
            return 1;
        }
        else {
            return 2;
        }
    }
    return 0;
}

BOOL cFileExtension(char* fileName) {
    std::string normalizedString(fileName);
    std::transform(normalizedString.begin(), normalizedString.end(), normalizedString.begin(), [](unsigned char c) {return std::tolower(c);  });
    bool match = std::any_of(suffixes.begin(), suffixes.end(), [&](const std::string & s) { return normalizedString.ends_with(s); });
    if (!match) {
        return false;
    }
    return true;
}

BOOL cFilePath(std::string filePath) {
    std::transform(filePath.begin(), filePath.end(), filePath.begin(), [](unsigned char c) {return std::tolower(c);  });
    bool match = std::any_of(pathPatterns.begin(), pathPatterns.end(), [&](const std::string& s) { return filePath.find(s) != std::string::npos; });
    if (!match) {
        return false;
    }
    return true;
}

int main(int argc, char* argv[])
{
    enableANSI();
    BOOL networkArg = true;
    std::string outputPath;
    std::vector<std::string> args(argv + 1, argv + argc);

    if (std::find(args.begin(), args.end(), "--no-network") != args.end()) {
        networkArg = false;
    }

    auto outIt = std::find(args.begin(), args.end(), "--output");
    if (outIt != args.end()) {
        if (outIt + 1 == args.end()) {
            std::cout << "[-] --output requires a file path" << std::endl;
            return 1;
        }
        outputPath = *(outIt + 1);
    }

    printHeader();

    if (!(isElevated())) {
        std::cout << "[-] Must run program with administrative privileges!" << std::endl;
        return 1;
    }
    LPVOID drivers[1024];
    DWORD lpcbNeeded;
    CHAR driverFilePath[1024];
    CHAR driverFileName[1024];
    int cDrivers = 0, i;
    std::vector<std::string> vFileExists, vFileExtension, vFilePath, vLolDrivers, vTrust, vExpiredCert;
    std::unordered_set<std::string> lolDriverHashes;

    std::cout << "\n[+] Checking system-level configuration settings..." << std::endl;
    ULONG ciBitmask = CodeIntegrityCheck();
    int vulnDriverCheck = RegistryValueCheck();

    BOOL enumDrivers = EnumDeviceDrivers(drivers, sizeof(drivers), &lpcbNeeded);

    if (networkArg) {
        std::cout << "[+] Gathering LOLDrivers list..." << std::endl;
        std::string lolDriverInfo = HTTPGetRequest(L"www.loldrivers.io", L"api/drivers.json");
        lolDriverHashes = buildHashSet(lolDriverInfo);
    }

    if (enumDrivers) {
        std::cout << "[+] Enumerating loaded drivers on system..." << std::endl;
        if (lpcbNeeded < sizeof(drivers)) {
            cDrivers = lpcbNeeded / sizeof(drivers[0]);
            std::cout << "[+] Performing driver check..." << std::endl;
            for (i = 0; i < cDrivers; i++) {
                DWORD eFilePath = GetDeviceDriverFileName(drivers[i], driverFilePath, sizeof(driverFilePath) / sizeof(driverFilePath[0]));
                DWORD eFileName = GetDeviceDriverBaseName(drivers[i], driverFileName, sizeof(driverFileName) / sizeof(driverFileName[0]));
                if (eFilePath == 0 || eFileName == 0) {
                    std::cout << "[-] Error retrieving driver information. Error: " << GetLastError() << std::endl;
                    return 2;
                }
                else {
                    std::string normalizedPath = resolveDriverPath(driverFilePath);
                    int fileExists = cFileExists(normalizedPath);
                    if (fileExists == 2) {
                        continue;
                    }
                    if (fileExists == 1) {
                        vFileExists.push_back(normalizedPath);
                        continue;
                    }
                    if (!cFileExtension(driverFileName)) {
                        for (char& c : normalizedPath) {
                            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        }
                        if (std::ranges::find(fExtensionTuning, normalizedPath) == fExtensionTuning.end()) {
                            vFileExtension.push_back(normalizedPath);
                        }
                    }
                    if (!cFilePath(normalizedPath)) {
                        vFilePath.push_back(normalizedPath);
                    }

                    if (networkArg) {
                        std::string fileHash = getSHA256(normalizedPath);
                        if (lolDriverHashes.contains(fileHash)) {
                            vLolDrivers.push_back(normalizedPath);
                        }
                    }
                    DriverSigInfo emb = verifyDriverSignatureEmbedded(normalizedPath);
                    BOOL trusted = emb.trusted;
                    BOOL certChecked = emb.certChecked;
                    BOOL certExpired = emb.certExpired;
                    if (!trusted || !certChecked) {
                        DriverSigInfo cat = verifyDriverSignatureCatalog(normalizedPath);
                        if (!trusted) trusted = cat.trusted;
                        if (!certChecked) { certChecked = cat.certChecked; certExpired = cat.certExpired; }
                    }
                    if (!trusted) vTrust.push_back(normalizedPath);
                    if (certExpired) vExpiredCert.push_back(normalizedPath);
                }
            }
        }

        std::string ciEnabled = ((ciBitmask & CODEINTEGRITY_OPTION_ENABLED) ? "YES" : "NO");
        std::string testSigning = ((ciBitmask & CODEINTEGRITY_OPTION_TESTSIGN) ? "YES" : "NO");
        std::string hvciEnabled = ((ciBitmask & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) ? "YES" : "NO");
        std::string hvciStrict = ((ciBitmask & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED) ? "YES" : "NO");

        std::string sVulnDriverCheck;
        switch (vulnDriverCheck) {
        case 0:
            sVulnDriverCheck = "YES";
            break;
        case 1:
            sVulnDriverCheck = "NO";
            break;
        case 2:
            sVulnDriverCheck = "N/A";
            break;
        }

        if (!outputPath.empty()) {
            if (writeJsonReport(outputPath, networkArg, vFileExists, vFileExtension, vFilePath, vTrust, vExpiredCert, vLolDrivers, ciEnabled, testSigning, hvciEnabled, hvciStrict, sVulnDriverCheck)) {
                std::cout << "[+] JSON report written to " << outputPath << std::endl;
            }
            else {
                std::cout << "[-] Failed to write JSON to " << outputPath << std::endl;
            }
        }
        clearScreen();
        printHeader();

        printSystemConfigs(ciEnabled, testSigning, hvciEnabled, hvciStrict, sVulnDriverCheck);

        size_t totalFlagged = vLolDrivers.size() + vTrust.size() + vExpiredCert.size() +
                              vFilePath.size() + vFileExtension.size() + vFileExists.size();

        printSummary(networkArg, vLolDrivers, vTrust, vExpiredCert, vFilePath, vFileExtension, vFileExists);

        if (networkArg) printSection("LOLDrivers", vLolDrivers, "[X]", "\033[91m");
        printSection("Trust Verification Failed", vTrust, "[!]", "\033[91m");
        printSection("Signing Certificate Expired at Signing Time", vExpiredCert, "[!]", "\033[91m");
        printSection("Abnormal File Path", vFilePath, "[?]", "\033[93m");
        printSection("Abnormal File Extension", vFileExtension, "[?]", "\033[93m");
        printSection("Nonexistent Files", vFileExists, "[?]", "\033[93m");

        std::cout << "\n[+] Scan complete \xe2\x80\x94 " << cDrivers << " drivers enumerated, "
                  << totalFlagged << " flagged." << std::endl;
    }
}