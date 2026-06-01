#pragma once
#include <string>

class PasswordEntry {
private:
    std::string site;
    std::string login;
    std::string password;

public:
    PasswordEntry() = default;
    PasswordEntry(const std::string& site, const std::string& login, const std::string& password);

    const std::string& getSite() const;
    const std::string& getLogin() const;
    const std::string& getPassword() const;

    void setSite(const std::string& newSite);
    void setLogin(const std::string& newLogin);
    void setPassword(const std::string& newPassword);
};