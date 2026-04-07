KERNEL CHEAT SHEET (Detection Engineer
Edition)
What is a Kernel?
Core component of an OS that manages hardware and system resources.
Core Responsibilities
- Process Management (scheduling, multitasking)
- Memory Management (RAM allocation, isolation)
- Device Management (drivers, disk, network)
- System Calls (API between apps and OS)
- Security (permissions, isolation)
Kernel vs User Space
User Space: Apps (limited access)
Kernel Space: Full system control
Compromise = full system takeover
Why It Matters for Detection Engineering
- EDR operates near kernel level
- Sysmon logs kernel-driven activity
- Rootkits and drivers abuse kernel
Key Telemetry to Monitor
- Process creation (parent-child anomalies)
- Driver loads
- File + registry changes
- Network connections from system processes
High-Risk Indicators
- Unsigned driver loads
- Kernel module injection
- SYSTEM-level processes spawning shells
- Direct memory access anomalies
Real Kernels
- Windows NT Kernel
- Linux Kernel
- XNU (macOS)
Simple Mental Model
Apps → Kernel → Hardware
Kernel = traffic controller for CPU, memory, and device