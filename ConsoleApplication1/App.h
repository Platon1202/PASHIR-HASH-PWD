#pragma once
#include <string>
#include "Vault.h"
#include "AuthManager.h"

class App {
private:
    std::string filename;
    Vault vault;
    AuthManager authManager;
    std::string currentMasterPassword;
    bool authenticated;

    void firstRunSetup();
    bool login();
    void mainMenu();

    void showEntries() const;
    void addEntry();
    void editEntry();
    void removeEntry();
    void generatePasswordOnly() const;
    void saveVault();

    std::string inputLine(const std::string& prompt) const;
    int inputInt(const std::string& prompt) const;

public:
    App(const std::string& filename);
    void run();
};