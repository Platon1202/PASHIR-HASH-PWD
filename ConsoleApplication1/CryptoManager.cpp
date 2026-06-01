#include "CryptoManager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

bool CryptoManager::generateRandomBytes(std::vector<unsigned char>& data, size_t size) {
    data.resize(size);

    if (size == 0) {
        return true;
    }

    return RAND_bytes(data.data(), static_cast<int>(size)) == 1;
}

std::vector<unsigned char> CryptoManager::deriveKeyPBKDF2(
    const std::string& password,
    const std::vector<unsigned char>& salt,
    int iterations,
    size_t keyLength
) {
    std::vector<unsigned char> key(keyLength);

    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(keyLength),
        key.data()
    );

    if (result != 1) {
        return {};
    }

    return key;
}

bool CryptoManager::encryptAESGCM(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& nonce,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag
) {
    if (key.size() != 32) {
        return false;
    }

    if (!generateRandomBytes(nonce, 12)) {
        return false;
    }

    tag.resize(16);
    ciphertext.resize(plaintext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int ok = 1;
    int len = 0;
    int ciphertextLen = 0;

    ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!plaintext.empty()) {
        ok = EVP_EncryptUpdate(
            ctx,
            ciphertext.data(),
            &len,
            plaintext.data(),
            static_cast<int>(plaintext.size())
        );
        if (ok != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ciphertextLen = len;
    }

    ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return ok == 1;
}

bool CryptoManager::decryptAESGCM(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext
) {
    if (key.size() != 32 || nonce.empty() || tag.size() != 16) {
        return false;
    }

    plaintext.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int ok = 1;
    int len = 0;
    int plaintextLen = 0;

    ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!ciphertext.empty()) {
        ok = EVP_DecryptUpdate(
            ctx,
            plaintext.data(),
            &len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())
        );
        if (ok != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        plaintextLen = len;
    }

    ok = EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_TAG,
        static_cast<int>(tag.size()),
        const_cast<unsigned char*>(tag.data())
    );
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok != 1) {
        return false;
    }

    plaintextLen += len;
    plaintext.resize(plaintextLen);
    return true;
}
