#pragma once
#include <string>
#include <vector>
#include <fstream>
#include "Vault.h"
#include "AuthManager.h"

class FileManager {
public:
    static bool fileExists(const std::string& filename);

    static bool saveVaultToFile(
        const std::string& filename,
        const Vault& vault,
        const AuthManager& authManager,
        const std::string& masterPassword
    );

    static bool loadAuthDataFromFile(
        const std::string& filename,
        AuthManager& authManager
    );

    static bool loadVaultFromFile(
        const std::string& filename,
        Vault& vault,
        AuthManager& authManager,
        const std::string& masterPassword
    );

private:
    static constexpr uint32_t VERSION = 1;

    static void writeUint32(std::ofstream& out, uint32_t value);
    static bool readUint32(std::ifstream& in, uint32_t& value);

    static void writeBytes(std::ofstream& out, const std::vector<unsigned char>& data);
    static bool readBytes(std::ifstream& in, std::vector<unsigned char>& data);

    static void writeString(std::vector<unsigned char>& buffer, const std::string& text);
    static bool readString(const std::vector<unsigned char>& buffer, size_t& offset, std::string& text);

    static std::vector<unsigned char> serializeVault(const Vault& vault);
    static bool deserializeVault(const std::vector<unsigned char>& data, Vault& vault);
};