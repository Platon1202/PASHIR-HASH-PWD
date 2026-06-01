#include "PasswordGenerator.h"
#include <random>

std::string PasswordGenerator::generate(size_t length, bool useUpper, bool useLower, bool useDigits, bool useSpecial) {
    std::string chars;

    if (useUpper) {
        chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
    if (useLower) {
        chars += "abcdefghijklmnopqrstuvwxyz";
    }
    if (useDigits) {
        chars += "0123456789";
    }
    if (useSpecial) {
        chars += "!@#$%^&*()-_=+[]{};:,.<>/?";
    }

    if (chars.empty() || length == 0) {
        return "";
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += chars[dist(gen)];
    }

    return result;
}