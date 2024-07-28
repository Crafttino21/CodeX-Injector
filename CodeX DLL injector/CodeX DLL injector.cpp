#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <ctime>
#include <cstdlib>
#include <string>

// ASCII-Art
void printAsciiArt()
{
    std::wcout << L"   _____          _     __   __\n";
    std::wcout << L"  / ____|        | |    \\ \\ / /\n";
    std::wcout << L" | |     ___   __| | ___ \\ V / \n";
    std::wcout << L" | |    / _ \\ / _` |/ _ \\ > <  \n";
    std::wcout << L" | |___| (_) | (_| |  __// . \\ \n";
    std::wcout << L"  \\_____\\___/ \\__,_|\\___/_/ \\_\\\n";
    std::wcout << L"\n";
}

std::wstring generateRandomTitle()
{
    const int length = 10; // Länge des Fenstertitels
    std::wstring title(length, L' ');
    static const wchar_t alphanum[] =
        L"0123456789"
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        L"abcdefghijklmnopqrstuvwxyz";

    std::srand(static_cast<unsigned int>(std::time(0))); // Initialisiert den Zufallszahlengenerator

    for (int i = 0; i < length; ++i)
    {
        title[i] = alphanum[std::rand() % (sizeof(alphanum) / sizeof(wchar_t) - 1)];
    }

    return title;
}

DWORD getProcId(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32FirstW(hSnap, &procEntry))
        {
            do
            {
                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
        CloseHandle(hSnap); // Handle schließen, wenn fertig
    }
    else
    {
        std::wcerr << L"[-] Failed to create snapshot. Error code: " << GetLastError() << "\n";
    }
    return procId;
}

int main()
{
    // ASCII-Art anzeigen
    printAsciiArt();

    // Setze den Fenstertitel auf einen zufälligen Wert
    std::wstring randomTitle = generateRandomTitle();
    SetConsoleTitleW(randomTitle.c_str());

    // Benutzer nach DLL-Pfad und Prozessnamen fragen
    std::wstring dllPath;
    std::wstring procName;

    std::wcout << L"Geben Sie den Pfad zur DLL ein: ";
    std::getline(std::wcin, dllPath);

    std::wcout << L"Geben Sie den Prozessnamen ein (z.B. GTA5.exe): ";
    std::getline(std::wcin, procName);

    std::wcout << L"[+] Using DLL path: " << dllPath << "\n";
    std::wcout << L"[+] Using process name: " << procName << "\n";

    std::wcout << L"[+] Attempting to get the process ID...\n";

    DWORD procId = 0;

    while (!procId)
    {
        procId = getProcId(procName.c_str());
        if (!procId)
        {
            std::wcout << L"[-] Process not found, retrying...\n";
            Sleep(1000);
        }
    }

    std::wcout << L"[+] Process found! Process ID: " << procId << "\n";

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        std::wcout << L"[+] Process opened successfully.\n";

        void* loc = VirtualAllocEx(hProc, 0, (dllPath.length() + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (loc)
        {
            std::wcout << L"[+] Memory allocated in the target process successfully at address: " << loc << "\n";

            if (WriteProcessMemory(hProc, loc, dllPath.c_str(), (dllPath.length() + 1) * sizeof(wchar_t), 0))
            {
                std::wcout << L"[+] DLL path written to the target process successfully.\n";

                HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, loc, 0, 0);

                if (hThread)
                {
                    std::wcout << L"[+] Remote thread created successfully.\n";
                    std::wcout << L"[+] Remote thread handle: " << hThread << "\n";

                    // Warten, bis der Remote-Thread abgeschlossen ist
                    WaitForSingleObject(hThread, INFINITE);

                    // Exit-Code des Remote-Threads abrufen
                    DWORD exitCode;
                    if (GetExitCodeThread(hThread, &exitCode))
                    {
                        std::wcout << L"[+] Remote thread exited with code: " << exitCode << "\n";
                        if (exitCode == 0)
                        {
                            std::wcerr << L"[-] LoadLibraryW failed in the remote process. Error code: " << GetLastError() << "\n";
                        }
                    }
                    else
                    {
                        std::wcerr << L"[-] Failed to get remote thread exit code. Error code: " << GetLastError() << "\n";
                    }

                    CloseHandle(hThread);
                }
                else
                {
                    std::wcerr << L"[-] Failed to create remote thread. Error code: " << GetLastError() << "\n";
                }
            }
            else
            {
                std::wcerr << L"[-] Failed to write DLL path to the target process. Error code: " << GetLastError() << "\n";
            }
        }
        else
        {
            std::wcerr << L"[-] Failed to allocate memory in the target process. Error code: " << GetLastError() << "\n";
        }

        CloseHandle(hProc);
    }
    else
    {
        std::wcerr << L"[-] Failed to open the process. Error code: " << GetLastError() << "\n";
    }

    std::wcout << L"[+] Injection complete. Waiting for 5 seconds before exit...\n";
    Sleep(5000); // Warten Sie 5 Sekunden

    return 0;
}
