#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <psapi.h>
#include <format>
#include <codecvt>
#include <locale>
#include <array>

// DirectX 11
#include <d3d11.h>
#include <dxgi.h>
#include <tchar.h>

// ImGui
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")


// DirectX 11 global variables
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

void CreateRenderTarget();
void CleanupDeviceD3D();
void CleanupRenderTarget();

// String conversion functions
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        NULL, 0, NULL, NULL);
    if (size_needed <= 0) return "";

    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        &str[0], size_needed, NULL, NULL);
    return str;
}

std::string WCharToString(const wchar_t* wstr) {
    if (!wstr) return "";
    return WStringToString(std::wstring(wstr));
}

// Data structures
struct ProcessInfo {
    DWORD pid;
    std::string name;
    uintptr_t baseAddress;
};

struct PointerLevel {
    std::string offset;
    uintptr_t resolvedAddress;
    uintptr_t value;
};

class ProcessPointerResolver {
private:
    HANDLE hProcess = nullptr;
    DWORD currentPid = 0;
    std::string currentProcessName;
    uintptr_t currentBaseAddress = 0;

    std::vector<ProcessInfo> processes;
    std::vector<PointerLevel> pointerChain;

    // Changed to char arrays for proper ImGui input
    char baseAddressInput[64] = "";
    std::vector<std::array<char, 64>> offsetInputs;

    // For direct memory read/write
    char memAddressInput[64] = "";
    char memWriteValueInput[64] = "";
    uintptr_t memValue = 0;
    bool readSuccess = false;
    bool writeSuccess = false;

    bool is64Bit = false;

    // Data type for memory editing
    enum DataType {
        TYPE_BYTE = 0,
        TYPE_SHORT,
        TYPE_INT,
        TYPE_LONG,
        TYPE_FLOAT,
        TYPE_DOUBLE,
        TYPE_COUNT
    };

    int selectedDataType = TYPE_INT;
    const char* dataTypeNames[TYPE_COUNT] = {
        "Byte (1 byte)",
        "Short (2 bytes)",
        "Int (4 bytes)",
        "Long (8 bytes)",
        "Float (4 bytes)",
        "Double (8 bytes)"
    };

    size_t dataTypeSizes[TYPE_COUNT] = { 1, 2, 4, 8, 4, 8 };

public:
    ProcessPointerResolver() {
        // Initialize with one empty offset buffer
        offsetInputs.push_back(std::array<char, 64>());
        offsetInputs[0][0] = '\0'; // Null terminate
        memWriteValueInput[0] = '\0';
    }

    ~ProcessPointerResolver() {
        closeProcess();
    }

    void refreshProcessList() {
        processes.clear();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                info.name = WCharToString(pe32.szExeFile);

                // Get base address
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
                if (hProc) {
                    HMODULE hMod;
                    DWORD cbNeeded;
                    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)) {
                        info.baseAddress = (uintptr_t)hMod;
                    }
                    CloseHandle(hProc);
                }

                processes.push_back(info);
            } while (Process32NextW(snapshot, &pe32));
        }

        CloseHandle(snapshot);
    }

    bool openProcess(DWORD pid, const std::string& name) {
        closeProcess();

        // Try with full access first (for writing)
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            // Try with fewer permissions (for reading only)
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }

        if (hProcess) {
            currentPid = pid;
            currentProcessName = name;

            // Check if process is 64-bit
            BOOL isWow64 = FALSE;
            IsWow64Process(hProcess, &isWow64);
            is64Bit = !isWow64;

            // Get base address
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                currentBaseAddress = (uintptr_t)hMod;
            }

            return true;
        }

        return false;
    }

    void closeProcess() {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        currentPid = 0;
        currentProcessName.clear();
        currentBaseAddress = 0;
        pointerChain.clear();
    }

    uintptr_t parseHex(const char* str) {
        if (!str || str[0] == '\0') return 0;

        try {
            return std::stoull(str, nullptr, 16);
        }
        catch (...) {
            return 0;
        }
    }

    bool readMemory(uintptr_t address, uintptr_t& value) {
        if (!hProcess) return false;

        SIZE_T bytesRead;
        if (is64Bit) {
            uint64_t buffer;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, &buffer, sizeof(uint64_t), &bytesRead)) {
                value = buffer;
                return bytesRead == sizeof(uint64_t);
            }
        }
        else {
            uint32_t buffer;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, &buffer, sizeof(uint32_t), &bytesRead)) {
                value = buffer;
                return bytesRead == sizeof(uint32_t);
            }
        }
        return false;
    }

    template<typename T>
    bool readMemory(uintptr_t address, T& value) {
        if (!hProcess) return false;

        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(T), &bytesRead)) {
            return bytesRead == sizeof(T);
        }
        return false;
    }

    template<typename T>
    bool writeMemory(uintptr_t address, const T& value) {
        if (!hProcess) return false;

        SIZE_T bytesWritten;
        if (WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), &bytesWritten)) {
            return bytesWritten == sizeof(T);
        }
        return false;
    }

    bool writeMemoryByType(uintptr_t address, const char* valueStr) {
        if (!valueStr || valueStr[0] == '\0') return false;

        try {
            switch (selectedDataType) {
            case TYPE_BYTE: {
                uint8_t value = static_cast<uint8_t>(std::stoul(valueStr, nullptr, 0));
                return writeMemory(address, value);
            }
            case TYPE_SHORT: {
                uint16_t value = static_cast<uint16_t>(std::stoul(valueStr, nullptr, 0));
                return writeMemory(address, value);
            }
            case TYPE_INT: {
                uint32_t value = static_cast<uint32_t>(std::stoul(valueStr, nullptr, 0));
                return writeMemory(address, value);
            }
            case TYPE_LONG: {
                uint64_t value = std::stoull(valueStr, nullptr, 0);
                return writeMemory(address, value);
            }
            case TYPE_FLOAT: {
                float value = std::stof(valueStr);
                return writeMemory(address, value);
            }
            case TYPE_DOUBLE: {
                double value = std::stod(valueStr);
                return writeMemory(address, value);
            }
            }
        }
        catch (...) {
            return false;
        }
        return false;
    }

    std::string readMemoryFormatted(uintptr_t address) {
        try {
            switch (selectedDataType) {
            case TYPE_BYTE: {
                uint8_t value;
                if (readMemory(address, value)) {
                    return std::format("0x{:02X} ({})", value, (int)value);
                }
                break;
            }
            case TYPE_SHORT: {
                uint16_t value;
                if (readMemory(address, value)) {
                    return std::format("0x{:04X} ({})", value, value);
                }
                break;
            }
            case TYPE_INT: {
                uint32_t value;
                if (readMemory(address, value)) {
                    return std::format("0x{:08X} ({})", value, value);
                }
                break;
            }
            case TYPE_LONG: {
                uint64_t value;
                if (readMemory(address, value)) {
                    return std::format("0x{:016X} ({})", value, value);
                }
                break;
            }
            case TYPE_FLOAT: {
                float value;
                if (readMemory(address, value)) {
                    return std::format("{:.6f}", value);
                }
                break;
            }
            case TYPE_DOUBLE: {
                double value;
                if (readMemory(address, value)) {
                    return std::format("{:.12f}", value);
                }
                break;
            }
            }
        }
        catch (...) {}
        return "Read failed";
    }

    void resolvePointerChain() {
        pointerChain.clear();

        if (!hProcess || baseAddressInput[0] == '\0') return;

        uintptr_t currentAddress = parseHex(baseAddressInput);

        for (size_t i = 0; i < offsetInputs.size(); i++) {
            if (offsetInputs[i][0] == '\0') continue;

            uintptr_t offset = parseHex(offsetInputs[i].data());
            PointerLevel level;
            level.offset = offsetInputs[i].data();

            if (i == 0) {
                // First level: base + offset
                level.resolvedAddress = currentAddress + offset;
            }
            else {
                // Subsequent levels: [address] + offset
                level.resolvedAddress = pointerChain[i - 1].value + offset;
            }

            if (!readMemory(level.resolvedAddress, level.value)) {
                level.value = 0;
            }

            pointerChain.push_back(level);
        }
    }

    void renderUI() {
        // Process selection
        if (ImGui::Button("Refresh Processes")) {
            refreshProcessList();
        }

        ImGui::SameLine();
        if (hProcess) {
            ImGui::Text("Current: %s (PID: %d)", currentProcessName.c_str(), currentPid);
            ImGui::SameLine();
            ImGui::Text(is64Bit ? " [64-bit]" : " [32-bit]");

            // Check if we have write access
            bool canWrite = true;
            HANDLE hTest = OpenProcess(PROCESS_VM_WRITE, FALSE, currentPid);
            if (!hTest) {
                canWrite = false;
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1, 0, 0, 1), " [Read-only]");
            }
            else {
                CloseHandle(hTest);
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0, 1, 0, 1), " [Read/Write]");
            }
        }
        else {
            ImGui::Text("No process selected");
        }

        // Process list
        ImGui::BeginChild("Process List", ImVec2(400, 200), true);
        for (const auto& proc : processes) {
            std::string label = std::format("{} (PID: {})", proc.name, proc.pid);
            if (ImGui::Selectable(label.c_str(), currentPid == proc.pid)) {
                openProcess(proc.pid, proc.name);
                sprintf_s(baseAddressInput, sizeof(baseAddressInput), "%llX", proc.baseAddress);
                resolvePointerChain();
            }
        }
        ImGui::EndChild();

        if (!hProcess) {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Please select a process");
            return;
        }

        ImGui::Separator();

        // Pointer chain input
        ImGui::Text("Pointer Chain Configuration:");

        // Base address
        ImGui::Text("Base Address:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200);

        // Fixed: Use char array instead of std::string
        if (ImGui::InputText("##Base", baseAddressInput, sizeof(baseAddressInput),
            ImGuiInputTextFlags_CharsHexadecimal)) {
            resolvePointerChain();
        }

        ImGui::SameLine();
        if (ImGui::Button("Set Default")) {
            sprintf_s(baseAddressInput, sizeof(baseAddressInput), "%llX", currentBaseAddress);
            resolvePointerChain();
        }

        // Offsets
        ImGui::Text("Offsets (Hex):");
        for (size_t i = 0; i < offsetInputs.size(); i++) {
            ImGui::PushID((int)i);

            ImGui::Text("Offset %d:", i + 1);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(150);

            // Fixed: Use char array instead of std::string
            bool offsetChanged = ImGui::InputText("##Offset", offsetInputs[i].data(),
                offsetInputs[i].size(),
                ImGuiInputTextFlags_CharsHexadecimal);

            ImGui::SameLine();
            if (ImGui::Button("+") && i == offsetInputs.size() - 1) {
                offsetInputs.push_back(std::array<char, 64>());
                offsetInputs.back()[0] = '\0';
            }

            ImGui::SameLine();
            if (ImGui::Button("-") && offsetInputs.size() > 1) {
                offsetInputs.erase(offsetInputs.begin() + i);
                offsetChanged = true;
            }

            if (offsetChanged) {
                resolvePointerChain();
            }

            ImGui::PopID();
        }

        // Resolve button
        if (ImGui::Button("Resolve Pointer Chain")) {
            resolvePointerChain();
        }

        ImGui::SameLine();
        if (ImGui::Button("Clear All")) {
            offsetInputs.clear();
            offsetInputs.push_back(std::array<char, 64>());
            offsetInputs[0][0] = '\0';
            pointerChain.clear();
        }

        ImGui::Separator();

        // Results
        ImGui::Text("Results:");
        if (pointerChain.empty()) {
            ImGui::Text("No pointer chain resolved");
        }
        else {
            ImGui::BeginChild("Results", ImVec2(0, 250), true);

            // Display as Cheat Engine style
            std::string chainDisplay = std::format("text\"{}\"+{:X}",
                currentProcessName, parseHex(baseAddressInput));

            for (size_t i = 0; i < offsetInputs.size(); i++) {
                if (offsetInputs[i][0] != '\0') {
                    chainDisplay += std::format(" -> 0x{}", offsetInputs[i].data());
                }
            }

            ImGui::TextWrapped("Pointer chain: %s", chainDisplay.c_str());
            ImGui::Separator();

            // Detailed view
            ImGui::Text("Detailed breakdown:");
            ImGui::Spacing();

            uintptr_t previousValue = parseHex(baseAddressInput);
            for (size_t i = 0; i < pointerChain.size(); i++) {
                const auto& level = pointerChain[i];

                ImGui::PushID((int)i + 1000);

                if (i == 0) {
                    // First level
                    ImGui::Text("Level %d: Base + Offset", i + 1);
                    ImGui::Text("  Base: 0x%llX", previousValue);
                    ImGui::Text("  Offset: +0x%s", level.offset.c_str());
                    ImGui::Text("  Address: 0x%llX", level.resolvedAddress);
                    ImGui::Text("  Value at address: 0x%llX", level.value);
                }
                else {
                    // Subsequent levels
                    ImGui::Text("Level %d: [Previous] + Offset", i + 1);
                    ImGui::Text("  Previous value: 0x%llX", previousValue);
                    ImGui::Text("  Offset: +0x%s", level.offset.c_str());
                    ImGui::Text("  Address: 0x%llX", level.resolvedAddress);
                    ImGui::Text("  Value at address: 0x%llX", level.value);
                }

                previousValue = level.value;

                if (i < pointerChain.size() - 1) {
                    ImGui::Separator();
                }

                ImGui::PopID();
            }

            // Final value with edit option
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "Final Value: 0x%llX",
                pointerChain.back().value);
            ImGui::TextColored(ImVec4(1, 1, 0, 1), "Final Address: 0x%llX",
                pointerChain.back().resolvedAddress);

            // Quick edit for final value
            ImGui::Spacing();
            if (ImGui::Button("Edit Final Value")) {
                sprintf_s(memAddressInput, sizeof(memAddressInput), "%llX",
                    pointerChain.back().resolvedAddress);
                sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "%llu",
                    pointerChain.back().value);
            }

            ImGui::EndChild();
        }

        ImGui::Separator();
        ImGui::Text("Memory Editor:");

        // Data type selection
        ImGui::Text("Data Type:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(150);
        ImGui::Combo("##DataType", &selectedDataType, dataTypeNames, TYPE_COUNT);

        // Memory reading/writing section
        ImGui::Text("Address:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("##Address", memAddressInput, sizeof(memAddressInput),
            ImGuiInputTextFlags_CharsHexadecimal);

        ImGui::SameLine();
        if (ImGui::Button("Read##Mem")) {
            uintptr_t address = parseHex(memAddressInput);
            readSuccess = readMemory(address, memValue);
        }

        ImGui::SameLine();
        if (ImGui::Button("Copy Final")) {
            if (!pointerChain.empty()) {
                sprintf_s(memAddressInput, sizeof(memAddressInput), "%llX",
                    pointerChain.back().resolvedAddress);
                // Read the current value
                readMemory(parseHex(memAddressInput), memValue);
            }
        }

        // Display current value
        if (memAddressInput[0] != '\0') {
            uintptr_t address = parseHex(memAddressInput);
            std::string formattedValue = readMemoryFormatted(address);
            ImGui::Text("Current value at 0x%s: %s", memAddressInput, formattedValue.c_str());
        }

        // Write section
        ImGui::Text("New Value:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("##NewValue", memWriteValueInput, sizeof(memWriteValueInput));

        ImGui::SameLine();
        if (ImGui::Button("Write##Mem")) {
            uintptr_t address = parseHex(memAddressInput);
            writeSuccess = writeMemoryByType(address, memWriteValueInput);
            if (writeSuccess) {
                // Update displayed value
                readMemory(address, memValue);
            }
        }

        // Write result feedback
        if (writeSuccess) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "Write successful!");
        }
        else if (memWriteValueInput[0] != '\0') {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Write failed!");
        }

        // Quick value buttons
        ImGui::Spacing();
        ImGui::Text("Quick Values:");

        if (ImGui::Button("Set 0")) {
            sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "0");
        }
        ImGui::SameLine();
        if (ImGui::Button("Set 1")) {
            sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "1");
        }
        ImGui::SameLine();
        if (ImGui::Button("Set 100")) {
            sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "100");
        }
        ImGui::SameLine();
        if (ImGui::Button("Set Max")) {
            switch (selectedDataType) {
            case TYPE_BYTE: sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "255"); break;
            case TYPE_SHORT: sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "65535"); break;
            case TYPE_INT: sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "4294967295"); break;
            case TYPE_LONG: sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "18446744073709551615"); break;
            default: sprintf_s(memWriteValueInput, sizeof(memWriteValueInput), "0"); break;
            }
        }

        // Memory protection warning
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "Warning: Modifying memory can cause crashes or instability.");
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "Make sure you know what you're doing!");
    }
};

// DirectX 11 Helper Functions
bool CreateDeviceD3D(HWND hWnd) {
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    // createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0
    };

    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags, featureLevelArray, 2,
        D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK) {
        return false;
    }

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();

    if (g_pSwapChain) {
        g_pSwapChain->Release();
        g_pSwapChain = nullptr;
    }

    if (g_pd3dDeviceContext) {
        g_pd3dDeviceContext->Release();
        g_pd3dDeviceContext = nullptr;
    }

    if (g_pd3dDevice) {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Create application window
    WNDCLASSEX wc = {
        sizeof(WNDCLASSEX),
        CS_CLASSDC,
        WndProc,
        0L,
        0L,
        GetModuleHandle(nullptr),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        _T("Pointer Resolver"),
        nullptr
    };

    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName,
        _T("Process Pointer Resolver - Memory Editor"),
        WS_OVERLAPPEDWINDOW,
        100, 100, 1280, 900,
        nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Application state
    ProcessPointerResolver resolver;
    resolver.refreshProcessList();

    // Main loop
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Create main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Process Pointer Resolver", nullptr,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        // Render UI
        resolver.renderUI();

        // FPS counter
        ImGui::Separator();
        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)",
            1000.0f / io.Framerate, io.Framerate);

        ImGui::End();

        // Rendering
        ImGui::Render();

        const float clear_color_with_alpha[4] = {
            0.1f, 0.1f, 0.1f, 1.0f
        };

        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // Present with vsync
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}