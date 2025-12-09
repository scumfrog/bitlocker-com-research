# Internal Architecture & Design Notes

This document details the internal structure of the Full Volume Encryption (FVE) COM Elevation POC and explains how each component works together to instantiate and interact with the undocumented BitLocker COM interface using Elevation Monikers.

---

## 1. High-Level Architecture

```
[ Process (Medium IL) ]
          |
          | CoGetObject("Elevation:Administrator!new:{CLSID}")
          v
[ Elevated COM Server (dllhost.exe, High IL) ]
          |
          | IDispatch::Invoke
          v
[ Undocumented FVE COM Interface ]
```

Key principles:
- Medium-integrity processes can instantiate *elevated* COM objects if the CLSID is elevation-enabled.
- The POC abstracts COM invocation through a small dynamic-dispatch layer.
- No type library exists, so all calls go through `IDispatch` with numeric DISPIDs.

---

## 2. Components

### **2.1 Elevation Manager**
Handles:
- Elevation detection (IsProcessElevated)
- Smart instantiation:
  - **Elevated process:** `CoCreateInstance`
  - **Standard process:** `CoGetObject` + elevation moniker
- COM security and initialization

### **2.2 FVE Dispatch Wrapper**
A lightweight wrapper to safely:
- Obtain an `IDispatch*`
- Invoke undocumented methods by `DISPID`
- Manage HRESULT propagation
- Log method results

Does *not* require any typelib.

---

## 3. Method Invocation Framework

Since the FVE interface is undocumented, calls follow this pattern:

```
IDispatch::Invoke(
    DispIdMember   = <FveMethodId>,
    riid           = IID_NULL,
    lcid           = LOCALE_USER_DEFAULT,
    wFlags         = DISPATCH_METHOD,
    pDispParams    = &params,
    pVarResult     = &result,
    pExcepInfo     = NULL,
    puArgErr       = NULL
);
```

Key properties:
- All methods are invoked as **methods** (not properties).
- Many FVE methods accept zero parameters.
- Return values vary depending on the operation performed.

---

## 4. Error Handling Model

The POC differentiates:

### **COM Layer Errors**
- Initialization failures  
- Security context failures  
- Elevation failures  
- `IDispatch::Invoke` COM exceptions  

### **FVE Internal Errors**
Return HRESULT codes from the BitLocker subsystem, such as:
- `0x80070005` – Access denied
- `0x80310000` – BitLocker generic failure
- `0x8031003A` – Encryption not enabled

All results are surfaced as exit codes.

---

## 5. Security Considerations (Developer Perspective)

- Elevation monikers cause Windows to spawn `dllhost.exe` at high integrity.
- The FVE COM server is not meant for public use, so defensive checks are minimal.
- The undocumented nature increases the risk of undefined behavior.

---

## 6. Extending the POC

You can easily add new undocumented FVE methods by:
1. Adding the DISPIDs to the enum.
2. Calling `FveComInvokeMethod(Dispatch, MethodId, &Result);`
3. Observing results in a VM.

Useful for:
- Enumerating volumes
- Testing unlock flows
- Checking policy enforcement

---

## 8. Disclaimer
This architecture is intended for research on Windows internals and COM elevation behavior.  
Running these methods will change encryption state — **never run on production machines**.
