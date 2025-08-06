// Layer 1 DoS Detector for Windows (Beginner/Intermediate Example)
// Monitors network adapters for link state changes and error bursts.
// Written by: 1rhino2
// Note: Compile with Visual Studio, link with wbemuuid.lib

// This is one of my first times working with hardware, but not my first time working in networking. I
#include <iostream>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

// This struct will help us keep track of each adapter's previous state
struct AdapterInfo
{
    std::wstring status;
    unsigned long long rx_errors;
    unsigned long long tx_errors;
};

// Helper function to print COM errors (MinGW/GCC compatible)
void printComError(const char *msg, HRESULT hr)
{
    wchar_t *errMsg = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errMsg,
        0,
        NULL);
    std::wcerr << L"[!] " << msg << L": " << (errMsg ? errMsg : L"Unknown error") << std::endl;
    if (errMsg)
        LocalFree(errMsg);
}

int main()
{
    HRESULT hres;

    // Initialize COM library
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        printComError("Failed to init COM", hres);
        return 1;
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                                NULL, EOAC_NONE, NULL);
    if (FAILED(hres))
    {
        printComError("Failed to set COM security", hres);
        CoUninitialize();
        return 1;
    }

    // Obtain the initial locator to WMI
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hres))
    {
        printComError("Failed to create IWbemLocator", hres);
        CoUninitialize();
        return 1;
    }

    // Connect to WMI namespace
    IWbemServices *pSvc = NULL;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hres = pLoc->ConnectServer(
        ns,   // namespace
        NULL, // user
        NULL, // password
        NULL, // locale
        0,    // security flags
        NULL, // authority
        NULL, // context
        &pSvc);
    SysFreeString(ns);
    if (FAILED(hres))
    {
        printComError("Failed to connect to WMI", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Set proxy blanket
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres))
    {
        printComError("Failed to set proxy blanket", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    std::wcout << L"Layer 1 DoS Detector\n";
    std::wcout << L"Monitoring link state and error counters. Ctrl+C to stop.\n";

    std::map<std::wstring, AdapterInfo> lastState;

    while (true)
    {
        IEnumWbemClassObject *pEnumerator = NULL;
        // Only select physical adapters with a NetConnectionID (ignore virtual/loopback)
        BSTR wql = SysAllocString(L"WQL");
        BSTR query = SysAllocString(L"SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True AND NetConnectionID IS NOT NULL");
        hres = pSvc->ExecQuery(
            wql,
            query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        SysFreeString(wql);
        SysFreeString(query);

        if (FAILED(hres))
        {
            printComError("Query failed", hres);
            break;
        }

        IWbemClassObject *pAdapter = NULL;
        ULONG uReturn = 0;

        while (pEnumerator && (pEnumerator->Next(WBEM_INFINITE, 1, &pAdapter, &uReturn) == S_OK))
        {
            VARIANT vName, vStatus, vNetID, vRxErr, vTxErr;
            pAdapter->Get(L"Name", 0, &vName, 0, 0);
            pAdapter->Get(L"NetConnectionStatus", 0, &vStatus, 0, 0); // 2 = up, 7 = down
            pAdapter->Get(L"NetConnectionID", 0, &vNetID, 0, 0);

            std::wstring name = vNetID.bstrVal ? vNetID.bstrVal : vName.bstrVal;
            std::wstring status = L"unknown";
            if (vStatus.vt == VT_I4)
            {
                if (vStatus.intVal == 2)
                    status = L"up";
                else if (vStatus.intVal == 7)
                    status = L"down";
                else
                    status = std::to_wstring(vStatus.intVal);
            }

            // Get error counts (may not be available on all adapters)
            unsigned long long rx_err = 0, tx_err = 0;
            if (SUCCEEDED(pAdapter->Get(L"InErrors", 0, &vRxErr, 0, 0)) && vRxErr.vt != VT_NULL)
            {
                rx_err = _wtoi64(vRxErr.bstrVal);
            }
            if (SUCCEEDED(pAdapter->Get(L"OutErrors", 0, &vTxErr, 0, 0)) && vTxErr.vt != VT_NULL)
            {
                tx_err = _wtoi64(vTxErr.bstrVal);
            }

            // Check if things changed
            if (lastState.count(name))
            {
                if (status != lastState[name].status)
                {
                    std::wcout << L"[!] Link state changed on " << name << L": "
                               << lastState[name].status << L" -> " << status << std::endl;
                }
                if (rx_err > 0 && rx_err - lastState[name].rx_errors > 10)
                {
                    std::wcout << L"[!] RX errors jumped on " << name << L": "
                               << lastState[name].rx_errors << L" -> " << rx_err << std::endl;
                }
                if (tx_err > 0 && tx_err - lastState[name].tx_errors > 10)
                {
                    std::wcout << L"[!] TX errors jumped on " << name << L": "
                               << lastState[name].tx_errors << L" -> " << tx_err << std::endl;
                }
            }
            // Update state
            lastState[name] = {status, rx_err, tx_err};

            VariantClear(&vName);
            VariantClear(&vStatus);
            VariantClear(&vNetID);
            VariantClear(&vRxErr);
            VariantClear(&vTxErr);
            pAdapter->Release();
        }
        if (pEnumerator)
            pEnumerator->Release();

        // Wait before next poll
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    // Clean up WMI
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return 0;
}