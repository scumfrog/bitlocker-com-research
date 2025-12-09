# FVE COM Elevation & Undocumented Interfaces

This document collects background information, hypothesis testing, undocumented behaviors, and experimental notes relevant during analysis of the FVE COM interface exposed by Windows.

---

## 1. Origins of the FVE COM Interface

BitLocker predates modern PowerShell cmdlets.  
Internally, Windows used COM to provide:

- Volume encryption/decryption management
- Policy/APIs for OEMs and enterprises
- UI hooks for early Control Panel integrations

Much of this legacy interface remains compiled but undocumented.

The CLSID:
```
{A7A63E5C-3877-4840-8727-C1EA9D7A4D50}
```
was originally registered for elevated usage by OEM tools.

---

## 2. Elevation Monikers: Behavior Observed

Key observations:

### No admin token needed for instantiation  
Windows elevates **only the COM server**, not the process.

### Minimal logging  
Event logs rarely track COM elevation use.

### CLSID must include `Elevation:Administrator!new:`  
Otherwise Windows returns:
```
0x80080005 (CO_E_SERVER_EXEC_FAILURE)
```

### UAC prompt only if:
- Process is medium IL  
- UAC is enabled  
- ConsentPromptBehaviorAdmin ≠ 0  

---

## 3. FVE Method Discovery

Since no IDL exists, DISPIDs were discovered by:

- Memory scanning of COM vtables
- Observing method invocation side-effects
- Reverse engineering `fvecpl.dll` and related modules
- Noting consistent ID ranges (700–800 region)

Example relevant DISPIDs:

| DISPID | Method Name                   | Notes |
|--------|------------------------------|-------|
| 519    | DoCheckForAdminRights        | Returns BOOL-like value |
| 769    | DoUnlockWithPassword         | Requires BSTR/password |
| 775    | DoDecrypt                    | Immediate volume decryption |
| 790    | DoTurnOnDeviceEncryption     | No params |
| 791    | DoTurnOffDeviceEncryption    | No params |

Side effects are immediate and extremely sensitive, test in a disposable VM only.

---

## 4. Behavioural Notes / Anomalies

### **4.1 COM Server Lifetime**
- COM server stays alive ~60 seconds after last call
- Lifetime extensions possible via `IMarshal`

### **4.2 Blocking Behaviour**
Some methods block until BitLocker background tasks finish.

### **4.3 Error Consistency**
FVE HRESULTs behave differently from classic Win32:
- Some return `S_OK` but set values in out parameters that indicate failure
- Others throw COM exceptions when given empty params

---

## 5. Security Angle: Why This Matters

These behaviors show a meaningful attack surface:

### **Elevation Without Traditional Paths**
Many EDRs do not inspect COM elevation behavior.

### **Privilege Boundary Crossing**
Medium-integrity → High-integrity transitions via Windows brokered elevation.

### **Possible Misuse Examples**
- Disabling device encryption
- Changing protection state silently
- Forensic evasion (unlock/decrypt volumes)

This research helps defenders close these blind spots.

---

## 6. Tooling Recommendations

To extend research:

### Reverse Engineering
- Ghidra + COM helper scripts
- `oleview.exe` or `oleviewdotnet`
- API Monitor (32/64-bit)

### Runtime Tracking
- Procmon with COM filters
- Sysmon Event ID 1/10
- ETW: `Microsoft-Windows-COMRuntime`

### Sandbox
Always use:
- Windows 10/11 VM snapshots
- Secure boot variants
- Different UAC settings

---

## 7. Future Research Directions

### 1. Explore more undocumented DISPIDs  
Likely 25–30 additional methods exist.

### 2. Cross-version comparison  
Windows 8 → 10 → 11 may reveal deprecated functionality.

### 3. Investigate related CLSIDs  
Notably in:
- Windows Update Agent
- Disk Management
- Task Scheduler Elevation Broker
- Device Management COM layers

### 4. Evaluate EDR detection gaps  
Most tools ignore `CoGetObject + Elevation:`.

---

## 8. Legal & Ethical Considerations

This research:
- **May modify system encryption state**
- **Is destructive when misused**
- **Must only be executed with explicit authorization**

You are fully responsible for safe handling and compliance.

---

## 9. Final Thoughts

The FVE COM interface represents a rare window into legacy Windows internals.  
By understanding it, researchers can:
- Improve Windows hardening
- Detect stealthy misuse
- Reveal undocumented attack surfaces

## 10. Disclaimer

This project and its accompanying code are based on a public proof-of-concept originally shared via social media by vx-underground, demonstrating how Windows Elevation Monikers can be used to instantiate undocumented Full Volume Encryption (FVE/BitLocker) COM interfaces.  [Original Post](https://x.com/vxunderground/status/1997999255001194887)

This material is provided **for educational and research purposes only**. It is **not intended for unauthorized system access, data destruction, bypassing security controls, or production deployment.**  

Always obtain explicit authorization before experimenting with system internals, encryption subsystems, or privileged operations. Use only in controlled test environments or dedicated research VMs.  
