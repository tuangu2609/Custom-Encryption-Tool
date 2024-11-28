#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <string>
using namespace std;
#define hardcodedHash 119979293 // Giá trị hash đã biết từ chuỗi gốc sau khi mã hóa 
static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
// Hàm RC4 đã mô tả trước đó
void RC4(PCHAR key, PCHAR input, PCHAR output, DWORD length) {
    unsigned char S[256];
    int len = strlen(key);
    int j = 0;
    unsigned char tmp;
    for (int i = 0; i < 256; i++)
        S[i] = i;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + ((PUCHAR)key)[i % len]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    int i = 0;
    j = 0;
    for (int n = 0; n < length; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        int rnd = S[(S[i] + S[j]) % 256];
        ((PUCHAR)output)[n] = rnd ^ ((PUCHAR)input)[n];
    }
}

unsigned int djb2Hash(const char* data, DWORD dataLength) {
    DWORD hash = 9876;
    for (int i = 0; i < dataLength; i++) {
        hash = ((hash << 5) + hash) + ((PBYTE)data)[i];
    }
    // printf("Hash: %u\n", hash);
    return hash;
}

PCHAR RecursiveCrack(PCHAR encryptedData, int encryptedDataLength, PCHAR key, int level) {
    char keySpace[] = "\x00""ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    PCHAR decryptedData = new char[encryptedDataLength + 1]();
    for (int i = 0; i < sizeof(keySpace) - 1; i++) {
        if (level == 16) {
            if (!i) i++;
            key[16 - level] = keySpace[i];
            RC4(key, encryptedData, decryptedData, encryptedDataLength);
            if (djb2Hash(decryptedData, encryptedDataLength) == hardcodedHash) return key;
            if (i == sizeof(keySpace) - 2) return NULL;
        }
        else {
            key[16 - level] = keySpace[i];
            if (RecursiveCrack(encryptedData, encryptedDataLength, key, level + 1) != NULL) return key;
            else continue;
        }
    }
    delete[] decryptedData;
    return NULL;
}

PCHAR CrackKey(PCHAR encryptedData, int encryptedDataLength) {
    PCHAR key = new char[16]();
    RecursiveCrack(encryptedData, encryptedDataLength, key, 1);
    printf("Key: %s\n", key);
    return key;
}

vector<int> obfuscation(const char* big_string, const char* original_string) {
    vector<int> offsets;
    for (int i = 0; i < strlen(original_string); ++i) {
        for (int j = 0; j < strlen(big_string); ++j) {
            if (original_string[i] == big_string[j]) {
                offsets.push_back(j);
                break;
            }
        }
    }
    return offsets;
}

string deObfuscation(const vector<int>& offsets, const char* big_string) {
    string result;
    for (int offset : offsets) {
        result += big_string[offset];
    }
    return result;
}

string simpleXOR(const string& data, char key) {
    string result = data;
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key;
    }
    return result;
}

vector<int> encodeString(const string& input, const char* big_string, char key) {
    // First obfuscation
    vector<int> obfuscated = obfuscation(big_string, input.c_str());
    
    // Convert to string
    string obfuscatedString;
    for (int offset : obfuscated) {
        obfuscatedString += to_string(offset) + ",";
    }
    
    // Encrypt
    string encrypted = simpleXOR(obfuscatedString, key);

    // Encode Base64
    string base64Encoded = base64_encode(encrypted);

    // Additional obfuscation using the same function
    return obfuscation(big_string, base64Encoded.c_str());
}

string decodeString(const vector<int>& encoded, const char* big_string, char key) {
    // Deobfuscate the Base64 encoded string
    string base64Encoded = deObfuscation(encoded, big_string);

    // Decode Base64
    string decoded = base64_decode(base64Encoded);
    
    // Decrypt
    string decrypted = simpleXOR(decoded, key);

    // Parse back to vector<int>
    vector<int> decryptedOffsets;
    stringstream ss(decrypted);
    string token;
    while (getline(ss, token, ',')) {
        if (!token.empty()) {
            decryptedOffsets.push_back(stoi(token));
        }
    }

    // Final deobfuscation
    return deObfuscation(decryptedOffsets, big_string);
}
// Add these new functions to extract strings

std::string convertShellcodeToString(const char* shellcode) {
    std::string result;
    size_t len = strlen(shellcode);
    for (size_t i = 0; i < len; i++) {
        if (shellcode[i] == '\\' && shellcode[i + 1] == 'x') {
            char byte = (char)strtol(shellcode + i + 2, nullptr, 16);
            result += byte;
            i += 3;
        } else {
            result += shellcode[i];
        }
    }
    return result;
}

bool isStringLiteral(const string& line, size_t pos) {
    return (line[pos] == '"' || (pos > 0 && line[pos-1] == 'L' && line[pos] == '"'));
}

bool shouldSkipLine(const string& line) {
    // Skip pragma directives
    if (line.find("#pragma") != string::npos) return true;
    
    // Skip include directives
    if (line.find("#include") != string::npos) return true;
    
    // Skip printf statements
    if (line.find("printf") != string::npos) return true;
    
    // Skip commented lines
    if (line.find("//") != string::npos) return true;
    
    return false;
}

vector<string> extractStrings(const string& filePath) {
    vector<string> strings;
    ifstream file(filePath);
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    
    // Check if content looks like shellcode (contains \x)
    if (content.find("\\x") != string::npos) {
        strings.push_back(convertShellcodeToString(content.c_str()));
    } else {
        // Original string extraction logic
        string line;
        ifstream file2(filePath);
        while (getline(file2, line)) {
            if (shouldSkipLine(line)) continue;
            size_t pos = 0;
            while ((pos = line.find("\"", pos)) != string::npos) {
                if (isStringLiteral(line, pos)) {
                    size_t end = line.find("\"", pos + 1);
                    if (end != string::npos) {
                        string str = line.substr(pos + 1, end - pos - 1);
                        if (!str.empty()) {
                            strings.push_back(str);
                        }
                        pos = end + 1;
                    } else {
                        break;
                    }
                } else {
                    pos++;
                }
            }
        }
    }
    return strings;
}


void showLoadingBar(int duration) {
    const int barWidth = 50;
    for (int i = 0; i <= barWidth; ++i) {
        float progress = (float)i / barWidth;
        int pos = barWidth * progress;
        
        std::cout << "\r[";
        for (int j = 0; j < barWidth; ++j) {
            if (j < pos) std::cout << "=";  // Using # instead of █
            else std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << "%";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(duration/barWidth));
    }
    std::cout << std::endl;
}

void displayBanner() {
    system("cls");  // Clear screen
    std::cout << "\033[1;36m" << R"(
    +==========================================+
    |     CUSTOM HARDCODE STRING ENCRYPTOR     |
    |      Advanced Encryption Solutions       |
    |        Version 1.0 FPT UNIVERSITY        |
    +==========================================+
    )" << "\033[0m" << std::endl;
}

void displayMenu() {
    std::cout << "\033[1;33m" << R"(
    [*] Available Operations:
    +==========================================+
    | 0. View Documentation                    |
    | 1. RC4 Encryption                        |
    | 2. Generate Security Hash                |
    | 3. String Obfuscation                    |
    | 4. Exit                                  |
    +==========================================+
    )" << "\033[0m";
}

int main() {
    SetConsoleTitle(L"Professional String Encryptor - Enterprise Edition");
    char key[] = "D0";
    const char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789=/+";
    char keyOb = 'K';

    int choice;
    
    displayBanner();
    std::cout << "\033[1;32m[+] Initializing encryption engine...\033[0m\n";
    showLoadingBar(500);
    
    while(true) {
        displayMenu();
        std::cout << "\033[1;37mSelect operation [0-4]: \033[0m";
        std::cin >> choice;
        std::cin.ignore();

        switch(choice) {
            case 0: {
                system("cls");
                std::cout << "\033[1;36m" << R"(
                +==================================================+
                |       CUSTOM HARDCODE STRING ENCRYPTOR v1.0      |
                |        Advanced Security Solutions Suite         |
                +==================================================+
                
                [TOOL DESCRIPTION]
                A comprehensive security tool designed for string manipulation,
                encryption, and obfuscation. Provides enterprise-grade protection
                for sensitive string data with multiple layers of security.

                [FEATURES]
                1. RC4 Encryption Suite
                - Source file string extraction & encryption
                - Multiple string processing capability
                - Base64 encoding integration
                - Real-time verification system
                
                2. Security Hash Generation
                - DJB2 hash algorithm implementation
                - String verification capabilities
                - Cryptographic integrity checks
                
                3. Advanced String Obfuscation
                - Multi-layer protection system
                - Direct input processing
                - File-based input support
                - Batch string processing
                
                [USAGE EXAMPLES]
                1. File Processing:
                - Input full path to source file
                - Supports both Windows and Unix paths
                - Example: C:\Projects\source.cpp or /home/user/source.cpp
                
                2. String Obfuscation:
                - Single string: "WSAStartup"
                - Multiple strings: "WSAStartup, WSAConnect, cmd.exe"
                - File input: strings.txt containing comma-separated values
                
                [SECURITY FEATURES]
                - Multi-layer encryption
                - Base64 encoding
                - Custom key implementation
                - Hash verification
                - Memory-safe operations
                
                [BEST PRACTICES]
                - Keep encryption keys secure
                - Use full file paths
                - Verify output with provided tools
                - Regular security updates
                - Maintain backup of original strings
                
                [TECHNICAL SPECIFICATIONS]
                - RC4 encryption implementation
                - Custom obfuscation algorithms
                - Base64 encoding/decoding
                - Hash generation using djb2
                - Unicode support
                
                [SUPPORT]
                For technical support or feature requests:
                - Documentation: github.com/tuangu
                - Issues: github.com/tuangu/issues
                - Version: 1.0 FPT University Edition
                )" << "\033[0m" << std::endl;

                std::cout << "\n\033[1;33mPress Enter to return to main menu...\033[0m";
                std::cin.get();
                system("cls");
                break;
            }

            case 1: {
                system("cls");
                displayBanner();
                int encryptionChoice;
                std::cout << "\033[1;33m[*] RC4 Encryption Options:\033[0m\n";
                std::cout << "\033[1;34m[1] Process Source File\033[0m\n";
                std::cout << "\033[1;34m[2] Input String Encryption\033[0m\n";
                std::cout << "\033[1;34m[3] Process MSF Payload\033[0m\n";
                std::cout << "\033[1;34m[>] Choice: \033[0m";
                std::cin >> encryptionChoice;
                std::cin.ignore();

                if (encryptionChoice == 1) {
                    system("cls");
                    displayBanner();
                    std::string filePath;
                    std::cout << "\033[1;34m[>] Enter full source file path\033[0m\n";
                    std::cout << "\033[1;33m[*] Example: C:\\Users\\Desktop\\source.cpp\033[0m\n";
                    std::cout << "\033[1;34m[>] Path: \033[0m";
                    getline(std::cin, filePath);

                    std::cout << "\033[1;34m[>] Operation:\033[0m\n";
                    std::cout << "\033[1;34m[1] Encrypt\033[0m\n";
                    std::cout << "\033[1;34m[2] Decrypt\033[0m\n";
                    std::cout << "\033[1;34m[>] Choice: \033[0m";
                    int operationType;
                    std::cin >> operationType;
                    std::cin.ignore();
                    
                    std::cout << "\033[1;32m[+] Analyzing file...\033[0m\n";
                    showLoadingBar(500);
                    
                    std::ifstream file(filePath);
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    
                    if (operationType == 1) {
                        string shellcode = convertShellcodeToString(content.c_str());
                        
                        char encryptedString[1024] = {0};
                        RC4(key, (PCHAR)shellcode.c_str(), encryptedString, shellcode.length());
                        string encryptedStdString(encryptedString, shellcode.length());
                        
                        string base64EncodedString = base64_encode(encryptedStdString);
                        
                        std::cout << "\033[1;36mOriginal Shellcode:\033[0m\n" << content << std::endl;
                        std::cout << "\033[1;35mEncrypted (Base64):\033[0m " << base64EncodedString << std::endl;
                        std::cout << "\033[1;35mEncrypted (bytes):\033[0m\n";
                        
                        const int BYTES_PER_LINE = 14;
                        int byteCount = 0;
                        std::cout << "\"";
                        for (char c : base64EncodedString) {
                            printf("\\x%02x", (unsigned char)c);
                            byteCount++;
                            if (byteCount % BYTES_PER_LINE == 0 && byteCount < base64EncodedString.length()) {
                                std::cout << "\"\n\"";
                            }
                        }
                        std::cout << "\"" << std::endl;
                    }
                else {
                    string shellcodeBytes = convertShellcodeToString(content.c_str());
                    
                    // Clean only the base64 formatting characters
                    string cleanBase64;
                    for (char c : shellcodeBytes) {
                        if (c != '"' && c != '\n' && c != '\r') {
                            cleanBase64 += c;
                        }
                    }

                    // Decode base64 to get the original encrypted bytes
                    string decodedString = base64_decode(cleanBase64);

                    // Decrypt directly without any byte filtering
                    char decryptedString[1024] = {0};
                    RC4(key, (PCHAR)decodedString.c_str(), decryptedString, decodedString.length());
                    
                    // Clean up the decrypted shellcode
                    string cleanedShellcode;
                    bool skipNext = false;
                    // Skip first \x22 if present
                    size_t start = (decryptedString[0] == 0x22) ? 1 : 0;
                    
                    for (size_t i = start; i < strlen(decryptedString); i++) {
                        if (skipNext) {
                            skipNext = false;
                            continue;
                        }
                        // Check for pattern \x22\x0a\x22
                        if (i + 2 < strlen(decryptedString) && 
                            (unsigned char)decryptedString[i] == 0x22 && 
                            (unsigned char)decryptedString[i+1] == 0x0a && 
                            (unsigned char)decryptedString[i+2] == 0x22) {
                            i += 2;
                            continue;
                        }
                        // Skip last \x22 if we're at the end
                        if (i == strlen(decryptedString) - 1 && (unsigned char)decryptedString[i] == 0x22) {
                            break;
                        }
                        cleanedShellcode += decryptedString[i];
                    }
                    printf("%s", cleanedShellcode.c_str());
                    // Output results
                    std::cout << "\033[1;36mEncrypted Input:\033[0m\n" << content << std::endl;
                    std::cout << "\033[1;32mDecrypted Shellcode:\033[0m\n";
                                        
                    // Print the cleaned shellcode bytes
                    const int BYTES_PER_LINE = 14;
                    int byteCount = 0;
                    std::cout << "\"";
                    for (size_t i = 0; i < cleanedShellcode.length(); i++) {
                        printf("\\x%02x", (unsigned char)cleanedShellcode[i]);
                        byteCount++;
                        if (byteCount % BYTES_PER_LINE == 0 && i < cleanedShellcode.length() - 1) {
                            std::cout << "\"\n\"";
                        }
                    }
                    std::cout << "\"" << std::endl;
                }

                std::cout << "\033[1;33m----------------------------------------\033[0m\n";
                std::cout << "\033[1;32m[+] Processing complete!\033[0m\n";
                showLoadingBar(500);
                break;

                }

                else if (encryptionChoice == 2) {
                    system("cls");
                    displayBanner();
                    
                    std::cout << "\033[1;34m[>] Input type:\033[0m\n";
                    std::cout << "\033[1;34m[1] Normal string\033[0m\n";
                    std::cout << "\033[1;34m[2] Shellcode\033[0m\n";
                    std::cout << "\033[1;34m[>] Choice: \033[0m";
                    int inputType;
                    std::cin >> inputType;
                    std::cin.ignore();

                    string inputString;
                    if (inputType == 1) {
                        std::cout << "\033[1;34m[>] Enter strings to encrypt (separate by comma):\033[0m\n";
                        std::cout << "\033[1;33m[*] Example: WSAStartup, WSAConnect, cmd.exe\033[0m\n";
                    } else {
                        std::cout << "\033[1;34m[>] Enter shellcode to encrypt:\033[0m\n";
                        std::cout << "\033[1;33m[*] Example: \\x48\\x31\\xc9\\x48\\x81\\xe9\033[0m\n";
                    }
                    std::cout << "\033[1;34m[>] Input: \033[0m";
                    getline(std::cin, inputString);

                    if (inputType == 2) {
                        inputString = convertShellcodeToString(inputString.c_str());
                    }
                    
                    std::cout << "\033[1;32m[+] Preparing encryption...\033[0m\n";
                    showLoadingBar(500);
                    
                    vector<string> strings_to_process;
                    if (inputType == 1) {
                        stringstream ss(inputString);
                        string token;
                        while (getline(ss, token, ',')) {
                            if (!token.empty()) {
                                token.erase(0, token.find_first_not_of(" "));
                                token.erase(token.find_last_not_of(" ") + 1);
                                strings_to_process.push_back(token);
                            }
                        }
                    } else {
                        strings_to_process.push_back(inputString);
                    }
                    
                    std::cout << "\033[1;33m[*] Processing " << strings_to_process.size() << " string(s)...\033[0m\n";
                    showLoadingBar(500);
                    
                    for (const auto& str : strings_to_process) {
                        char encryptedString[1024] = {0};
                        char decryptedString[1024] = {0};
                        
                        RC4(key, (PCHAR)str.c_str(), encryptedString, str.length());
                        string encryptedStdString(encryptedString, str.length());
                        string base64EncodedString = base64_encode(encryptedStdString);
                        string decodedString = base64_decode(base64EncodedString);
                        RC4(key, (PCHAR)decodedString.c_str(), decryptedString, decodedString.length());
                        
                        std::cout << "\n\033[1;32m[+] Results for string: " << str << "\033[0m\n";
                        std::cout << "\033[1;36mOriginal:\033[0m          " << str << std::endl;
                        std::cout << "\033[1;35mEncrypted (Base64):\033[0m " << base64EncodedString << std::endl;
                        std::cout << "\033[1;35mEncrypted (bytes):\033[0m\n";
                        const int BYTES_PER_LINE = 14;  // Same as input format
                        int byteCount = 0;
                        std::cout << "\"";
                        for (char c : encryptedStdString) {
                            printf("\\x%02x", (unsigned char)c);
                            byteCount++;
                            if (byteCount % BYTES_PER_LINE == 0 && byteCount < encryptedStdString.length()) {
                                std::cout << "\"\n\"";
                            }
                        }
                        std::cout << "\"" << std::endl;
                        std::cout << "\033[1;32mDecrypted:\033[0m         " << decryptedString << std::endl;
                        std::cout << "\033[1;33m----------------------------------------\033[0m\n";
                    }
                    
                    std::cout << "\033[1;32m[+] Operation completed successfully!\033[0m\n";
                    showLoadingBar(500);
                    break;
                }

                // Add new case for MSF payload handling
                else if (encryptionChoice == 3) {
                    system("cls");
                    displayBanner();
                    std::string filePath;
                    std::cout << "\033[1;34m[>] Enter MSF payload path (.bin file)\033[0m\n";
                    std::cout << "\033[1;33m[*] Example: C:\\payloads\\calc.bin\033[0m\n";
                    std::cout << "\033[1;34m[>] Path: \033[0m";
                    getline(std::cin, filePath);
                    
                    std::cout << "\033[1;32m[+] Reading MSF payload...\033[0m\n";
                    showLoadingBar(500);
                    
                    // Read and process binary payload
                    std::ifstream file(filePath, std::ios::binary);
                    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
                    string shellcode(buffer.begin(), buffer.end());
                    
                    char encryptedString[1024] = {0};
                    RC4(key, (PCHAR)shellcode.c_str(), encryptedString, shellcode.length());
                    string encryptedStdString(encryptedString, shellcode.length());
                    string base64EncodedString = base64_encode(encryptedStdString);
                    
                    // Output results
                    std::cout << "\033[1;36mPayload Size:\033[0m " << shellcode.length() << " bytes\n";
                    std::cout << "\033[1;35mEncrypted Payload (Base64):\033[0m\n" << base64EncodedString << std::endl;
                    std::cout << "\033[1;35mEncrypted Payload (C format):\033[0m\n";
                    
                    const int BYTES_PER_LINE = 14;
                    int byteCount = 0;
                    std::cout << "unsigned char payload[] = \n\"";
                    for (char c : base64EncodedString) {
                        printf("\\x%02x", (unsigned char)c);
                        byteCount++;
                        if (byteCount % BYTES_PER_LINE == 0 && byteCount < base64EncodedString.length()) {
                            std::cout << "\"\n\"";
                        }
                    }
                    std::cout << "\";" << std::endl;
                }
                break;
            }

            case 2: {
                system("cls");
                displayBanner();
                string baseString;
                std::cout << "\033[1;34m[>] Enter base string for hash generation: \033[0m";
                getline(std::cin, baseString);
                
                std::cout << "\033[1;32m[+] Initializing hash generator...\033[0m\n";
                showLoadingBar(500);
                
                std::cout << "\033[1;33m[*] Computing hash...\033[0m\n";
                showLoadingBar(500);
                
                int generatedHash = djb2Hash(baseString.c_str(), baseString.length());
                
                std::cout << "\n\033[1;32m[+] Hash Generation Results:\033[0m\n";
                std::cout << "\033[1;36mInput String:\033[0m    " << baseString << std::endl;
                std::cout << "\033[1;35mGenerated Hash:\033[0m  " << generatedHash << std::endl;
                std::cout << "\033[1;33m----------------------------------------\033[0m\n";
                
                std::cout << "\033[1;32m[+] Hash generation complete!\033[0m\n";
                showLoadingBar(500);
                break;
            }

            case 3: {
                system("cls");
                displayBanner();
                int obfuscationChoice;
                std::cout << "\033[1;33m[*] Choose obfuscation input method:\033[0m\n";
                std::cout << "\033[1;34m[1] Direct string input\033[0m\n";
                std::cout << "\033[1;34m[2] Read from file\033[0m\n";
                std::cout << "\033[1;34m[>] Choice: \033[0m";
                std::cin >> obfuscationChoice;
                std::cin.ignore();

                string inputString;
                if (obfuscationChoice == 1) {
                    std::cout << "\033[1;34m[>] Enter string(s) to obfuscate (separate multiple strings with comma):\033[0m\n";
                    std::cout << "\033[1;33m[*] Example: WSAStartup, WSAConnect, cmd.exe\033[0m\n";
                    std::cout << "\033[1;34m[>] Input: \033[0m";
                    getline(std::cin, inputString);
                }
                else if (obfuscationChoice == 2) {
                    std::cout << "\033[1;34m[>] Enter full file path:\033[0m\n";
                    std::cout << "\033[1;33m[*] Example: C:\\strings.txt\033[0m\n";
                    std::cout << "\033[1;34m[>] Path: \033[0m";
                    string filePath;
                    getline(std::cin, filePath);
                    
                    ifstream inputFile(filePath);
                    if (!inputFile.is_open()) {
                        std::cout << "\033[1;31m[!] Error: Could not open file\033[0m\n";
                        break;
                    }
                    getline(inputFile, inputString);
                    inputFile.close();
                }

                std::cout << "\033[1;32m[+] Initializing obfuscation engine...\033[0m\n";
                showLoadingBar(500);
                
                vector<string> strings_to_process;
                stringstream ss(inputString);
                string token;
                
                while (getline(ss, token, ',')) {
                    if (!token.empty()) {
                        token.erase(0, token.find_first_not_of(" "));
                        token.erase(token.find_last_not_of(" ") + 1);
                        strings_to_process.push_back(token);
                    }
                }
                
                std::cout << "\033[1;33m[*] Processing " << strings_to_process.size() << " string(s)...\033[0m\n";
                showLoadingBar(500);
                
                for (const auto& str : strings_to_process) {
                    vector<int> encoded = encodeString(str, big_string, keyOb);
                    string decoded = decodeString(encoded, big_string, keyOb);
                    
                    std::cout << "\n\033[1;32m[+] Results for string: " << str << "\033[0m\n";
                    std::cout << "\033[1;35mObfuscated Array:\033[0m   ";
                    for (int i : encoded) {
                        cout << i << " ";
                    }
                    std::cout << std::endl;
                    
                    std::cout << "\033[1;35mFormatted Array:\033[0m    {";
                    for (size_t i = 0; i < encoded.size(); ++i) {
                        cout << encoded[i];
                        if (i < encoded.size() - 1) {
                            cout << ", ";
                        }
                    }
                    cout << "}" << std::endl;
                    
                    std::cout << "\033[1;32mVerification:\033[0m       " << decoded << std::endl;
                    std::cout << "\033[1;33m----------------------------------------\033[0m\n";
                }
                
                std::cout << "\033[1;32m[+] Obfuscation complete!\033[0m\n";
                showLoadingBar(500);
                break;
            }

            case 4: {
                std::cout << "\033[1;32m[+] Shutting down safely...\033[0m\n";
                showLoadingBar(500);
                return 0;
            }
        }
            
            std::cout << "\n\033[1;37mPress Enter to continue...\033[0m";
            std::cin.get();
            system("cls");
            displayBanner();
        }
    return 0;
}


