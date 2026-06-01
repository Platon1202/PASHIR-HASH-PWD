#include "App.h"
#include "FileManager.h"
#include "PasswordGenerator.h"
#include <iostream>
#include <limits>

App::App(const std::string& filename)
    : filename(filename), authenticated(false) {
}

std::string App::inputLine(const std::string& prompt) const {
    std::string value;
    std::cout << prompt;
    std::getline(std::cin, value);
    return value;
}

int App::inputInt(const std::string& prompt) const {
    int value;
    while (true) {
        std::cout << prompt;
        if (std::cin >> value) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return value;
        }

        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Incorrect input. Enter a number.\n";
    }
}

void App::firstRunSetup() {
    std::cout << "No vault file found. First launch.\n";
    std::cout << "Create master password.\n";
    std::cout << "Requirements: at least 8 characters, upper/lowercase letters, digit, special symbol.\n";

    while (true) {
        std::string password1 = inputLine("Master password: ");
        std::string password2 = inputLine("Repeat master password: ");

        if (password1 != password2) {
            std::cout << "Passwords do not match.\n";
            continue;
        }

        if (!authManager.registerMasterPassword(password1)) {
            std::cout << "Password is too weak.\n";
            continue;
        }

        currentMasterPassword = password1;
        authenticated = true;

        if (!FileManager::saveVaultToFile(filename, vault, authManager, currentMasterPassword)) {
            std::cout << "Error while creating vault file.\n";
        }
        else {
            std::cout << "Vault created successfully.\n";
        }

        break;
    }
}

bool App::login() {
    if (!FileManager::loadAuthDataFromFile(filename, authManager)) {
        std::cout << "Failed to read authentication data.\n";
        return false;
    }

    const int maxAttempts = 5;

    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        std::string password = inputLine("Enter master password: ");

        if (authManager.verifyMasterPassword(password)) {
            Vault loadedVault;
            AuthManager authForLoad;

            if (!FileManager::loadVaultFromFile(filename, loadedVault, authForLoad, password)) {
                std::cout << "Failed to decrypt vault.\n";
                return false;
            }

            vault = loadedVault;
            authManager = authForLoad;
            currentMasterPassword = password;
            authenticated = true;

            std::cout << "Login successful.\n";
            return true;
        }

        std::cout << "Wrong password. Attempts left: " << (maxAttempts - attempt) << '\n';
    }

    std::cout << "Too many failed attempts. Program will exit.\n";
    return false;
}

void App::showEntries() const {
    vault.printAll();
}

void App::addEntry() {
    std::string site = inputLine("Site: ");
    std::string login = inputLine("Login: ");

    std::cout << "1. Enter password manually\n";
    std::cout << "2. Generate password\n";
    int choice = inputInt("Choice: ");

    std::string password;

    if (choice == 2) {
        int length = inputInt("Password length: ");
        if (length <= 0) {
            std::cout << "Invalid length.\n";
            return;
        }

        password = PasswordGenerator::generate(static_cast<size_t>(length));
        std::cout << "Generated password: " << password << '\n';
    }
    else {
        password = inputLine("Password: ");
    }

    if (vault.addEntry(PasswordEntry(site, login, password))) {
        std::cout << "Entry added.\n";
    }
    else {
        std::cout << "Failed to add entry.\n";
    }
}

void App::editEntry() {
    if (vault.isEmpty()) {
        std::cout << "Vault is empty.\n";
        return;
    }

    vault.printAll();
    int number = inputInt("Entry number to edit: ");

    if (number <= 0 || static_cast<size_t>(number) > vault.size()) {
        std::cout << "Invalid entry number.\n";
        return;
    }

    std::string site = inputLine("New site: ");
    std::string login = inputLine("New login: ");

    std::cout << "1. Enter new password manually\n";
    std::cout << "2. Generate new password\n";
    int choice = inputInt("Choice: ");

    std::string password;

    if (choice == 2) {
        int length = inputInt("Password length: ");
        if (length <= 0) {
            std::cout << "Invalid length.\n";
            return;
        }

        password = PasswordGenerator::generate(static_cast<size_t>(length));
        std::cout << "Generated password: " << password << '\n';
    }
    else {
        password = inputLine("New password: ");
    }

    if (vault.editEntry(static_cast<size_t>(number - 1), PasswordEntry(site, login, password))) {
        std::cout << "Entry updated.\n";
    }
    else {
        std::cout << "Failed to update entry.\n";
    }
}

void App::removeEntry() {
    if (vault.isEmpty()) {
        std::cout << "Vault is empty.\n";
        return;
    }

    vault.printAll();
    int number = inputInt("Entry number to delete: ");

    if (number <= 0 || static_cast<size_t>(number) > vault.size()) {
        std::cout << "Invalid entry number.\n";
        return;
    }

    if (vault.removeEntry(static_cast<size_t>(number - 1))) {
        std::cout << "Entry deleted.\n";
    }
    else {
        std::cout << "Failed to delete entry.\n";
    }
}

void App::generatePasswordOnly() const {
    int length = inputInt("Password length: ");
    if (length <= 0) {
        std::cout << "Invalid length.\n";
        return;
    }

    std::string password = PasswordGenerator::generate(static_cast<size_t>(length));
    std::cout << "Generated password: " << password << '\n';
}

void App::saveVault() {
    if (!authenticated) {
        std::cout << "User is not authenticated.\n";
        return;
    }

    if (FileManager::saveVaultToFile(filename, vault, authManager, currentMasterPassword)) {
        std::cout << "Vault saved successfully.\n";
    }
    else {
        std::cout << "Failed to save vault.\n";
    }
}

void App::mainMenu() {
    while (true) {
        std::cout << "\n=== Password Manager ===\n";
        std::cout << "1. Show entries\n";
        std::cout << "2. Add entry\n";
        std::cout << "3. Edit entry\n";
        std::cout << "4. Delete entry\n";
        std::cout << "5. Generate password\n";
        std::cout << "6. Save vault\n";
        std::cout << "0. Exit\n";

        int choice = inputInt("Choice: ");

        switch (choice) {
        case 1:
            showEntries();
            break;
        case 2:
            addEntry();
            break;
        case 3:
            editEntry();
            break;
        case 4:
            removeEntry();
            break;
        case 5:
            generatePasswordOnly();
            break;
        case 6:
            saveVault();
            break;
        case 0:
            saveVault();
            std::cout << "Exiting program.\n";
            return;
        default:
            std::cout << "Unknown menu item.\n";
            break;
        }
    }
}

void App::run() {
    if (!FileManager::fileExists(filename)) {
        firstRunSetup();
    }
    else {
        if (!login()) {
            return;
        }
    }

    if (authenticated) {
        mainMenu();
    }
}