#include "FileManager.h"
#include "CryptoManager.h"
#include <filesystem>
#include <cstdint>

bool FileManager::fileExists(const std::string& filename) {
    return std::filesystem::exists(filename);
}

void FileManager::writeUint32(std::ofstream& out, uint32_t value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

bool FileManager::readUint32(std::ifstream& in, uint32_t& value) {
    in.read(reinterpret_cast<char*>(&value), sizeof(value));
    return in.good();
}

void FileManager::writeBytes(std::ofstream& out, const std::vector<unsigned char>& data) {
    writeUint32(out, static_cast<uint32_t>(data.size()));
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
}

bool FileManager::readBytes(std::ifstream& in, std::vector<unsigned char>& data) {
    uint32_t size = 0;
    if (!readUint32(in, size)) {
        return false;
    }

    data.resize(size);
    if (size > 0) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        if (!in.good()) {
            return false;
        }
    }

    return true;
}

void FileManager::writeString(std::vector<unsigned char>& buffer, const std::string& text) {
    uint32_t len = static_cast<uint32_t>(text.size());
    const unsigned char* lenPtr = reinterpret_cast<const unsigned char*>(&len);
    buffer.insert(buffer.end(), lenPtr, lenPtr + sizeof(len));
    buffer.insert(buffer.end(), text.begin(), text.end());
}

bool FileManager::readString(const std::vector<unsigned char>& buffer, size_t& offset, std::string& text) {
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }

    uint32_t len = *reinterpret_cast<const uint32_t*>(&buffer[offset]);
    offset += sizeof(uint32_t);

    if (offset + len > buffer.size()) {
        return false;
    }

    text.assign(
        reinterpret_cast<const char*>(&buffer[offset]),
        reinterpret_cast<const char*>(&buffer[offset]) + len
    );
    offset += len;

    return true;
}

std::vector<unsigned char> FileManager::serializeVault(const Vault& vault) {
    std::vector<unsigned char> buffer;

    uint32_t count = static_cast<uint32_t>(vault.getEntries().size());
    const unsigned char* countPtr = reinterpret_cast<const unsigned char*>(&count);
    buffer.insert(buffer.end(), countPtr, countPtr + sizeof(count));

    for (const auto& entry : vault.getEntries()) {
        writeString(buffer, entry.getSite());
        writeString(buffer, entry.getLogin());
        writeString(buffer, entry.getPassword());
    }

    return buffer;
}

bool FileManager::deserializeVault(const std::vector<unsigned char>& data, Vault& vault) {
    vault.clear();

    if (data.size() < sizeof(uint32_t)) {
        return false;
    }

    size_t offset = 0;
    uint32_t count = *reinterpret_cast<const uint32_t*>(&data[offset]);
    offset += sizeof(uint32_t);

    for (uint32_t i = 0; i < count; ++i) {
        std::string site;
        std::string login;
        std::string password;

        if (!readString(data, offset, site)) {
            return false;
        }
        if (!readString(data, offset, login)) {
            return false;
        }
        if (!readString(data, offset, password)) {
            return false;
        }

        if (!vault.addEntry(PasswordEntry(site, login, password))) {
            return false;
        }
    }

    return true;
}

bool FileManager::saveVaultToFile(
    const std::string& filename,
    const Vault& vault,
    const AuthManager& authManager,
    const std::string& masterPassword
) {
    if (!authManager.hasStoredData()) {
        return false;
    }

    std::vector<unsigned char> encSalt;
    if (!CryptoManager::generateRandomBytes(encSalt, 16)) {
        return false;
    }

    std::vector<unsigned char> key = CryptoManager::deriveKeyPBKDF2(
        masterPassword,
        encSalt,
        AuthManager::PBKDF2_ITERATIONS,
        32
    );

    if (key.size() != 32) {
        return false;
    }

    std::vector<unsigned char> plaintext = serializeVault(vault);
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    if (!CryptoManager::encryptAESGCM(plaintext, key, nonce, ciphertext, tag)) {
        return false;
    }

    std::string tempFilename = filename + ".tmp";
    std::ofstream out(tempFilename, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }

    const char magic[4] = { 'P', 'A', 'S', 'H' };
    out.write(magic, 4);

    writeUint32(out, VERSION);
    writeBytes(out, authManager.getAuthSalt());
    writeBytes(out, authManager.getAuthHash());
    writeBytes(out, encSalt);
    writeBytes(out, nonce);
    writeBytes(out, tag);
    writeBytes(out, ciphertext);

    out.close();
    if (!out) {
        return false;
    }

    std::error_code ec;
    std::filesystem::remove(filename, ec);
    ec.clear();
    std::filesystem::rename(tempFilename, filename, ec);

    if (ec) {
        std::filesystem::remove(tempFilename);
        return false;
    }

    return true;
}

bool FileManager::loadAuthDataFromFile(
    const std::string& filename,
    AuthManager& authManager
) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    char magic[4];
    in.read(magic, 4);
    if (!in || magic[0] != 'P' || magic[1] != 'A' || magic[2] != 'S' || magic[3] != 'H') {
        return false;
    }

    uint32_t version = 0;
    if (!readUint32(in, version)) {
        return false;
    }

    if (version != VERSION) {
        return false;
    }

    std::vector<unsigned char> authSalt;
    std::vector<unsigned char> authHash;

    if (!readBytes(in, authSalt)) {
        return false;
    }
    if (!readBytes(in, authHash)) {
        return false;
    }

    authManager.setStoredAuthData(authSalt, authHash);
    return true;
}

bool FileManager::loadVaultFromFile(
    const std::string& filename,
    Vault& vault,
    AuthManager& authManager,
    const std::string& masterPassword
) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    char magic[4];
    in.read(magic, 4);
    if (!in || magic[0] != 'P' || magic[1] != 'A' || magic[2] != 'S' || magic[3] != 'H') {
        return false;
    }

    uint32_t version = 0;
    if (!readUint32(in, version)) {
        return false;
    }

    if (version != VERSION) {
        return false;
    }

    std::vector<unsigned char> authSalt;
    std::vector<unsigned char> authHash;
    std::vector<unsigned char> encSalt;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> ciphertext;

    if (!readBytes(in, authSalt)) {
        return false;
    }
    if (!readBytes(in, authHash)) {
        return false;
    }
    if (!readBytes(in, encSalt)) {
        return false;
    }
    if (!readBytes(in, nonce)) {
        return false;
    }
    if (!readBytes(in, tag)) {
        return false;
    }
    if (!readBytes(in, ciphertext)) {
        return false;
    }

    authManager.setStoredAuthData(authSalt, authHash);

    if (!authManager.verifyMasterPassword(masterPassword)) {
        return false;
    }

    std::vector<unsigned char> key = CryptoManager::deriveKeyPBKDF2(
        masterPassword,
        encSalt,
        AuthManager::PBKDF2_ITERATIONS,
        32
    );

    if (key.size() != 32) {
        return false;
    }

    std::vector<unsigned char> plaintext;
    if (!CryptoManager::decryptAESGCM(ciphertext, key, nonce, tag, plaintext)) {
        return false;
    }

    return deserializeVault(plaintext, vault);
}