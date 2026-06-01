#include "Vault.h"
#include <iostream>

PasswordEntry::PasswordEntry(const std::string& site, const std::string& login, const std::string& password)
    : site(site), login(login), password(password) {
}

const std::string& PasswordEntry::getSite() const {
    return site;
}

const std::string& PasswordEntry::getLogin() const {
    return login;
}

const std::string& PasswordEntry::getPassword() const {
    return password;
}

void PasswordEntry::setSite(const std::string& newSite) {
    site = newSite;
}

void PasswordEntry::setLogin(const std::string& newLogin) {
    login = newLogin;
}

void PasswordEntry::setPassword(const std::string& newPassword) {
    password = newPassword;
}

bool Vault::addEntry(const PasswordEntry& entry) {
    if (entry.getSite().empty() || entry.getLogin().empty()) {
        return false;
    }

    entries.push_back(entry);
    return true;
}

bool Vault::editEntry(size_t index, const PasswordEntry& updatedEntry) {
    if (index >= entries.size()) {
        return false;
    }

    if (updatedEntry.getSite().empty() || updatedEntry.getLogin().empty()) {
        return false;
    }

    entries[index] = updatedEntry;
    return true;
}

bool Vault::removeEntry(size_t index) {
    if (index >= entries.size()) {
        return false;
    }

    entries.erase(entries.begin() + index);
    return true;
}

const std::vector<PasswordEntry>& Vault::getEntries() const {
    return entries;
}

bool Vault::isEmpty() const {
    return entries.empty();
}

size_t Vault::size() const {
    return entries.size();
}

void Vault::clear() {
    entries.clear();
}

void Vault::printAll() const {
    if (entries.empty()) {
        std::cout << "The vault is empty (no saved passwords)\n";
        return;
    }

    for (size_t i = 0; i < entries.size(); ++i) {
        std::cout << i + 1 << ". "
            << "Site: " << entries[i].getSite()
            << ", Login: " << entries[i].getLogin()
            << ", Password: " << entries[i].getPassword()
            << '\n';
    }
}