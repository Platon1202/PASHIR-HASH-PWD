#pragma once
#include <string>
#include <vector>

class AuthManager {
private:
    std::vector<unsigned char> authSalt;
    std::vector<unsigned char> authHash;
    bool registered;

    bool isStrongPassword(const std::string& password) const;

public:
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t HASH_SIZE = 32;
    static constexpr int PBKDF2_ITERATIONS = 100000;

    AuthManager();

    bool registerMasterPassword(const std::string& masterPassword);
    bool verifyMasterPassword(const std::string& masterPassword) const;

    void setStoredAuthData(
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& hash
    );

    bool hasStoredData() const;

    const std::vector<unsigned char>& getAuthSalt() const;
    const std::vector<unsigned char>& getAuthHash() const;
};