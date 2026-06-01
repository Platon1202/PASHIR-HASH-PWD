#include <iostream>
#include <windows.h>
#include "App.h"

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    App app("vault.dat");
    app.run();

    return 0;
}