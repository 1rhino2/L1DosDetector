# Layer 1 DoS Detector (Windows, C++)

A simple, effective tool to monitor for **Layer 1 (Physical) Denial-of-Service** attempts on Windows systems.  
This project is written with clarity and best practices for C++/Windows WMI, making it ideal for both red and blue team exercises and learning hardware/network interactions.

---

## Features

- **Monitors all physical network adapters** (ignores virtual/loopback)
- **Detects link state changes** (e.g., cable unplugged/plugged)
- **Detects sudden RX/TX error bursts** (physical jamming, port flapping, failing hardware)
- **Beginner-friendly, robust code**
- **No dependencies except Windows and MSVC**

---

## Quick Start

### Prerequisites

- Windows 10, 11, or Server (Admin recommended for full stats)
- Visual Studio or MSVC build tools

### Build

1. Clone/download this repo.
2. Open a **Developer Command Prompt for VS**.
3. Compile:
   ```
   cl /EHsc layer1_dos_detector.cpp /link wbemuuid.lib
   ```
4. Run as Administrator:
   ```
   layer1_dos_detector.exe
   ```

---

## How To Test

1. **Start the detector** as above.
2. **Unplug and replug** a network cable, or disable/enable a network adapter in Windows Device Manager.
3. **Watch the console:**  
   You should see output such as:
   ```
   [!] Link state changed on Ethernet: up -> down
   [!] Link state changed on Ethernet: down -> up
   ```
4. **(Optional)**: Use a network stress/jamming tool or misconfigure cabling to trigger RX/TX error jumps.  
   Result:
   ```
   [!] RX errors jumped on Ethernet: 10 -> 25
   [!] TX errors jumped on Wi-Fi: 3 -> 18
   ```

**Tip:**  
If you want to simulate errors without hardware, use software tools that can flood interfaces or misconfigure the connection.

---

## Code Review & Improvements

- **Error Handling:** Good coverage for all COM/WMI steps; logs failures and cleans up resources.
- **Performance:** Polls every 2 seconds—can be adjusted for more/less sensitivity.
- **Extensibility:** You could log to a file, integrate with alerting, or even build a GUI.
- **Documentation:** Inline comments and a concise README for easy onboarding.

### Suggestions

- Make error thresholds and polling time configurable via CLI args.
- Add more granular event logging.
- Optionally, send events to SIEM, syslog, or Windows Event Log.

---

## References

- [Win32_NetworkAdapter WMI](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapter)
- [WMI C++ Example](https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer)
- [OSI Model: Layer 1](https://en.wikipedia.org/wiki/OSI_model#Layer_1:_Physical_layer)

---

## License
MIT 
