#pragma once
#include <string>
#include <vector>

class CryptoManager {
public:
    static bool generateRandomBytes(std::vector<unsigned char>& data, size_t size);

    static std::vector<unsigned char> deriveKeyPBKDF2(
        const std::string& password,
        const std::vector<unsigned char>& salt,
        int iterations,
        size_t keyLength
    );

    static bool encryptAESGCM(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& key,
        std::vector<unsigned char>& nonce,
        std::vector<unsigned char>& ciphertext,
        std::vector<unsigned char>& tag
    );

    static bool decryptAESGCM(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& nonce,
        const std::vector<unsigned char>& tag,
        std::vector<unsigned char>& plaintext
    );
};