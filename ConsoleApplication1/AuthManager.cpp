#include "AuthManager.h"
#include "CryptoManager.h"
#include <cctype>

AuthManager::AuthManager() : registered(false) {
}

bool AuthManager::isStrongPassword(const std::string& password) const {
    if (password.size() < 8) {
        return false;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (unsigned char ch : password) {
        if (std::isupper(ch)) {
            hasUpper = true;
        }
        else if (std::islower(ch)) {
            hasLower = true;
        }
        else if (std::isdigit(ch)) {
            hasDigit = true;
        }
        else {
            hasSpecial = true;
        }
    }

    return hasUpper && hasLower && hasDigit && hasSpecial;
}

bool AuthManager::registerMasterPassword(const std::string& masterPassword) {
    if (!isStrongPassword(masterPassword)) {
        return false;
    }

    if (!CryptoManager::generateRandomBytes(authSalt, SALT_SIZE)) {
        return false;
    }

    authHash = CryptoManager::deriveKeyPBKDF2(
        masterPassword,
        authSalt,
        PBKDF2_ITERATIONS,
        HASH_SIZE
    );

    if (authHash.size() != HASH_SIZE) {
        authSalt.clear();
        authHash.clear();
        registered = false;
        return false;
    }

    registered = true;
    return true;
}

bool AuthManager::verifyMasterPassword(const std::string& masterPassword) const {
    if (!registered) {
        return false;
    }

    std::vector<unsigned char> derived = CryptoManager::deriveKeyPBKDF2(
        masterPassword,
        authSalt,
        PBKDF2_ITERATIONS,
        HASH_SIZE
    );

    if (derived.size() != authHash.size()) {
        return false;
    }

    return derived == authHash;
}

void AuthManager::setStoredAuthData(
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& hash
) {
    authSalt = salt;
    authHash = hash;
    registered = !authSalt.empty() && !authHash.empty();
}

bool AuthManager::hasStoredData() const {
    return registered;
}

const std::vector<unsigned char>& AuthManager::getAuthSalt() const {
    return authSalt;
}

const std::vector<unsigned char>& AuthManager::getAuthHash() const {
    return authHash;
}