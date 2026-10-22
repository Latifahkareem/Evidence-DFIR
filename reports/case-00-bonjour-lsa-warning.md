
# Case 00: Origin of Bonjour and the LSA Protection Warning

**Date:** 2026-10-22
**Type:** Lab / personal training machine
**Examiner:** <your name or handle>
**Tools:** PowerShell (`Get-WinEvent`), Windows Settings (Installed apps), Windows Event Viewer

## 1. Summary

After installing FTK Imager and Autopsy, Windows displayed a Program Compatibility Assistant warning stating that Local Security Authority (LSA) protection blocked the module `mdnsNSP.dll` from loading (`Program Files\Bonjour`). I investigated which installation introduced Bonjour.

**Finding:** Bonjour 3.1.0.1 and Apple Mobile Device Support were installed during the FTK Imager installation transaction. Autopsy installation events do not overlap with the Apple components. The warning is most likely caused by LSA protection blocking an unsigned-by-Microsoft module from a legitimate Apple component, not by malicious activity.

## 2. Question

Where did Bonjour come from, and is the warning a sign of compromise?

## 3. Evidence

| Source | Details |
|---|---|
| Windows Installer events | Application log, provider `MsiInstaller`, filtered to 2026-10-22 |
| Installed apps list | Bonjour, Apple Inc., version 3.1.0.1, 4.62 MB, install date matches 2026-10-22 |
| Warning dialog | `\Device\HarddiskVolume3\Program Files\Bonjour\mdnsNSP.dll` blocked by LSA protection |

Command used:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'; StartTime=(Get-Date).Date} | Select TimeCreated, Message | Format-List
```

## 4. Timeline (local time, 2026-10-22)

| Time | Event |
|---|---|
| 09:48 - 09:49 | First Autopsy 4.23.1 install completes successfully |
| 09:54 - 09:56 | Several Autopsy reconfigure/install attempts end with error 1602 (installation cancelled or interrupted) |
| 09:58 - 09:59 | Second installer file (duplicate download) completes |
| 10:01 | Autopsy removed |
| 10:10 | Two further Autopsy install attempts fail with error 1602 |
| 10:10 - 10:11 | Autopsy 4.23.1 reinstalled successfully (final state: one working install) |
| 10:12 - 10:13 | CodeMeter Runtime Kit v8.20 (WIBU-SYSTEMS) installed |
| 10:18:20 | FTK Imager installer (`.msi`) transaction begins |
| 10:18:50 | Apple Mobile Device Support 18.0.0.33 installed |
| 10:19:01 | **Bonjour 3.1.0.1 installed** |
| 10:19:10 | Exterro FTK Imager 8.3.0.27 installation completes |

## 5. Analysis

- Bonjour and Apple Mobile Device Support appear between the start and end of the FTK Imager installer transaction, with no other installer running in that window. This points to the FTK Imager installer as the source.
- The Autopsy events contain no Apple components.
- CodeMeter Runtime Kit is a licensing component and was installed shortly before FTK Imager, which is consistent with it being a dependency of the FTK Imager installer.
- The repeated Autopsy 1602 errors are explained by two downloads of the same installer and by cancelled or repeated runs. The final state is a single successful installation.
- The warning is generated because LSA protection only allows modules that meet its signing requirements, and `mdnsNSP.dll` was blocked from loading into the LSA process.

## 6. Limitations

- The link between FTK Imager and Bonjour is inferred from timing in the event log. I did not verify it against vendor documentation.
- Signature verification of `mdnsNSP.dll` result: **<fill in: Valid / publisher name, or "not yet checked">**

```powershell
Get-AuthenticodeSignature "C:\Program Files\Bonjour\mdnsNSP.dll" | Format-List
```

## 7. Conclusion and Recommendation

- Most likely cause: components bundled with the FTK Imager installer (inferred from timing).
- No evidence of malicious activity found in the installer log.
- Dismiss the warning; do **not** disable LSA protection.
- Optional: run a full Microsoft Defender scan, and uninstall Bonjour only if Apple device support in FTK Imager is not needed (then test that FTK Imager still launches).

## 8. Lessons Learned

- Installer events in the Application log (`MsiInstaller`) give a reliable timeline of software installs.
- Correlating timestamps across events is often enough to identify which action caused a change.
- Always state whether a conclusion is proven or inferred.
