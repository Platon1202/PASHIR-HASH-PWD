#pragma once
#include <string>

class PasswordGenerator {
public:
    static std::string generate(
        size_t length,
        bool useUpper = true,
        bool useLower = true,
        bool useDigits = true,
        bool useSpecial = true
    );
};