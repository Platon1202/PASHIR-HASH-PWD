#pragma once
#include <vector>
#include "PasswordEntry.h"

class Vault {
private:
    std::vector<PasswordEntry> entries;

public:
    bool addEntry(const PasswordEntry& entry);
    bool editEntry(size_t index, const PasswordEntry& updatedEntry);
    bool removeEntry(size_t index);

    const std::vector<PasswordEntry>& getEntries() const;
    bool isEmpty() const;
    size_t size() const;
    void clear();

    void printAll() const;
};