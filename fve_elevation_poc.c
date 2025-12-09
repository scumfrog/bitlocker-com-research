#include <Windows.h>
#include <objbase.h>
#include <objidl.h>

enum FveMethodId
{
    DoTurnOffDeviceEncryption = 791,
    DoTurnOnDeviceEncryption = 790,
    DoUnlockWithPassword = 769,
    DoDecrypt = 775,
    DoCheckForAdminRights = 519,
};

// Secure memory zeroing using volatile to prevent compiler optimization
VOID SecureZeroMemory2(_Inout_ PVOID Destination, _In_ SIZE_T Size)
{
    volatile BYTE* ptr = (volatile BYTE*)Destination;
    while (Size--) {
        *ptr++ = 0;
    }
}

// Convert HRESULT to Win32 error code
DWORD Win32FromHResult(_In_ HRESULT Result)
{
    if ((Result & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
        return HRESULT_CODE(Result);

    if (Result == S_OK)
        return ERROR_SUCCESS;

    return ERROR_CAN_NOT_COMPLETE;
}

// Check if current process is running with elevated privileges
BOOL IsProcessElevated()
{
    BOOL bElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    
    TOKEN_ELEVATION Elevation = { 0 };
    DWORD dwSize = sizeof(TOKEN_ELEVATION);
    
    if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize)) {
        bElevated = Elevation.TokenIsElevated;
    }
    
    CloseHandle(hToken);
    return bElevated;
}

// Generic method to invoke FVE COM methods
HRESULT FveComInvokeMethod(
    _In_ IDispatch* Dispatch,
    _In_ DISPID MethodId,
    _Out_ HRESULT* MethodResult)
{
    HRESULT Result = S_OK;
    EXCEPINFO ExceptionInfo = { 0 };
    UINT ArgError = 0;

    if (!Dispatch || !MethodResult)
        return E_INVALIDARG;

    *MethodResult = E_FAIL;

    DISPPARAMS Parameters = { 0 };
    VARIANT Variant;
    VariantInit(&Variant);

    Result = Dispatch->Invoke(
        MethodId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &Parameters,
        &Variant,
        &ExceptionInfo,
        &ArgError
    );

    if (!SUCCEEDED(Result))
        goto EXIT_ROUTINE;

    // Handle different return types
    switch (Variant.vt) {
        case VT_I4:
            *MethodResult = (HRESULT)Variant.lVal;
            break;
        case VT_UI4:
            *MethodResult = (HRESULT)Variant.ulVal;
            break;
        case VT_ERROR:
            *MethodResult = Variant.scode;
            break;
        case VT_EMPTY:
            *MethodResult = S_OK;
            break;
        default:
            Result = E_UNEXPECTED;
            break;
    }

EXIT_ROUTINE:
    VariantClear(&Variant);
    
    if (ExceptionInfo.bstrSource) SysFreeString(ExceptionInfo.bstrSource);
    if (ExceptionInfo.bstrDescription) SysFreeString(ExceptionInfo.bstrDescription);
    if (ExceptionInfo.bstrHelpFile) SysFreeString(ExceptionInfo.bstrHelpFile);

    return Result;
}

// Initialize COM with proper error handling
HRESULT InitializeComSilently()
{
    HRESULT Result;
    
    Result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (Result == RPC_E_CHANGED_MODE) {
        CoUninitialize();
        Result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    }
    
    if (!SUCCEEDED(Result))
        return Result;

    Result = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IDENTIFY,
        NULL,
        EOAC_NONE,
        NULL
    );

    // Security already initialized is acceptable
    if (Result == RPC_E_TOO_LATE)
        Result = S_OK;

    return Result;
}

// Attempt direct COM instantiation without elevation
HRESULT TryDirectComAccess(_Out_ IDispatch** ppDispatch)
{
    CLSID ClsidFve = { 0xA7A63E5C, 0x3877, 0x4840, { 0x87, 0x27, 0xC1, 0xEA, 0x9D, 0x7A, 0x4D, 0x50 } };
    
    if (!ppDispatch)
        return E_INVALIDARG;

    *ppDispatch = NULL;

    // Try direct instantiation - works if already elevated
    return CoCreateInstance(
        ClsidFve,
        NULL,
        CLSCTX_LOCAL_SERVER,
        IID_IDispatch,
        (PVOID*)ppDispatch
    );
}

// Get elevated COM object using Elevation Moniker
HRESULT GetElevatedFveDispatch(_Out_ IDispatch** ppDispatch)
{
    HRESULT Result;
    WCHAR MonikerString[77] = L"Elevation:Administrator!new:{A7A63E5C-3877-4840-8727-C1EA9D7A4D50}";
    BIND_OPTS3 BindOptions = { 0 };

    if (!ppDispatch)
        return E_INVALIDARG;

    *ppDispatch = NULL;

    BindOptions.cbStruct = sizeof(BIND_OPTS3);
    BindOptions.dwClassContext = CLSCTX_LOCAL_SERVER;

    // This will trigger UAC prompt if needed
    Result = CoGetObject(MonikerString, &BindOptions, IID_IDispatch, (PVOID*)ppDispatch);
    
    return Result;
}

// Main execution flow
INT main(VOID)
{
    HRESULT Result = S_OK;
    HRESULT MethodResult = E_FAIL;
    IDispatch* Dispatch = NULL;
    DWORD ExitCode = ERROR_SUCCESS;
    BOOL bAlreadyElevated = FALSE;

    // Initialize COM subsystem
    Result = InitializeComSilently();
    if (!SUCCEEDED(Result)) {
        ExitCode = Win32FromHResult(Result);
        goto EXIT_ROUTINE;
    }

    // Check if already elevated to avoid unnecessary UAC prompt
    bAlreadyElevated = IsProcessElevated();

    // Try direct access first if already elevated
    if (bAlreadyElevated) {
        Result = TryDirectComAccess(&Dispatch);
    }

    // If direct access failed or not elevated, use Elevation Moniker
    if (!Dispatch) {
        Result = GetElevatedFveDispatch(&Dispatch);
        if (!SUCCEEDED(Result)) {
            ExitCode = Win32FromHResult(Result);
            goto EXIT_ROUTINE;
        }
    }

    // Invoke the target method
    Result = FveComInvokeMethod(Dispatch, DoTurnOffDeviceEncryption, &MethodResult);
    if (!SUCCEEDED(Result)) {
        ExitCode = Win32FromHResult(Result);
        goto EXIT_ROUTINE;
    }

    // Set exit code based on method result
    ExitCode = SUCCEEDED(MethodResult) ? ERROR_SUCCESS : Win32FromHResult(MethodResult);

EXIT_ROUTINE:
    if (Dispatch)
        Dispatch->Release();
    
    CoUninitialize();

    return ExitCode;
}
