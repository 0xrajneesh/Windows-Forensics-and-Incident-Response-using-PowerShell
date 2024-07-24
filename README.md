# Windows Forensics and Incident Response using PowerShell

## Introduction

Windows PowerShell is a powerful tool for performing forensic analysis and incident response on Windows systems. This advanced-level lab will guide you through various forensic and incident response tasks using PowerShell. You will learn to investigate user accounts, processes, services, scheduled tasks, registry entries, internet connections, file shares, files, firewall settings, sessions, and log entries.

## Pre-requisites

- Advanced knowledge of Windows operating systems
- Familiarity with forensic principles and techniques
- Understanding of PowerShell scripting
- Basic knowledge of network and system security concepts

## Lab Set-up and Tools

- A Windows computer or virtual machine
- [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell) installed
- Administrator access on the Windows system

## Exercises

### Exercise 1: Investigating User Accounts

**Objective**: Use PowerShell to list and investigate user accounts on the system.

1. List all local user accounts:
    ```powershell
    Get-LocalUser
    ```
2. List members of the Administrators group:
    ```powershell
    Get-LocalGroupMember Administrators
    ```
3. Display detailed information for a specific user:
    ```powershell
    Get-LocalUser -Name "username" | Format-List *
    ```

**Expected Output**: Information about all user accounts and members of the Administrators group.

### Exercise 2: Checking Running Processes

**Objective**: Use PowerShell to list and analyze running processes on the system.

1. List all running processes:
    ```powershell
    Get-Process | Format-Table -AutoSize
    ```
2. Display detailed information for a specific process:
    ```powershell
    Get-Process -Id PID | Format-List *
    ```
3. List processes with their parent process IDs:
    ```powershell
    Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId | Format-Table -AutoSize
    ```

**Expected Output**: Information about running processes, including details and parent process IDs.

### Exercise 3: Investigating Services

**Objective**: Use PowerShell to list and analyze services running on the system.

1. List all services:
    ```powershell
    Get-Service | Format-Table -AutoSize
    ```
2. Display detailed information for a specific service:
    ```powershell
    Get-Service -Name "servicename" | Format-List *
    ```
3. List services associated with running processes:
    ```powershell
    Get-WmiObject Win32_Service | Select-Object Name, DisplayName, ProcessId | Format-Table -AutoSize
    ```

**Expected Output**: Information about all services and details of specific services.

### Exercise 4: Checking Scheduled Tasks

**Objective**: Use PowerShell to list and investigate scheduled tasks on the system.

1. List all scheduled tasks:
    ```powershell
    Get-ScheduledTask | Format-Table -AutoSize
    ```
2. Display detailed information for a specific task:
    ```powershell
    Get-ScheduledTask -TaskName "taskname" | Format-List *
    ```
3. Disable a specific scheduled task:
    ```powershell
    Disable-ScheduledTask -TaskName "taskname"
    ```

**Expected Output**: Information about all scheduled tasks and details of specific tasks.

### Exercise 5: Investigating Registry Entries

**Objective**: Use PowerShell to investigate registry entries related to startup programs.

1. List startup programs from HKLM:
    ```powershell
    Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Format-Table -AutoSize
    ```
2. List startup programs from HKCU:
    ```powershell
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Format-Table -AutoSize
    ```
3. Display detailed information for a specific registry entry:
    ```powershell
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "entryname"
    ```

**Expected Output**: Information about startup programs from the registry.

### Exercise 6: Checking Active Internet Connections

**Objective**: Use PowerShell to list and investigate active internet connections.

1. List all active TCP connections:
    ```powershell
    Get-NetTCPConnection | Format-Table -AutoSize
    ```
2. Display detailed information for connections on a specific port:
    ```powershell
    Get-NetTCPConnection -LocalPort portnumber | Format-Table -AutoSize
    ```
3. List connections with process names:
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Format-Table -AutoSize
    ```

**Expected Output**: Information about all active TCP connections, including process names.

### Exercise 7: Investigating File Shares

**Objective**: Use PowerShell to list and investigate file shares on the system.

1. List all file shares:
    ```powershell
    Get-SmbShare | Format-Table -AutoSize
    ```
2. Display detailed information for a specific share:
    ```powershell
    Get-SmbShare -Name "sharename" | Format-List *
    ```
3. List active file share sessions:
    ```powershell
    Get-SmbSession | Format-Table -AutoSize
    ```

**Expected Output**: Information about all file shares and active sessions.

### Exercise 8: Investigating Files

**Objective**: Use PowerShell to list and investigate files in a specific directory.

1. List all files in the user profile directory:
    ```powershell
    Get-ChildItem -Path $env:userprofile -Recurse | Format-Table Name, FullName, LastWriteTime -AutoSize
    ```
2. List executable files created or modified in the last day:
    ```powershell
    Get-ChildItem -Path $env:userprofile -Recurse -Include *.exe | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Format-Table Name, FullName, LastWriteTime -AutoSize
    ```
3. Display detailed information for a specific file:
    ```powershell
    Get-Item -Path "filepath" | Format-List *
    ```

**Expected Output**: Information about files in the user profile directory and details of specific files.

### Exercise 9: Checking Firewall Settings

**Objective**: Use PowerShell to check and analyze firewall settings on the system.

1. List all firewall rules:
    ```powershell
    Get-NetFirewallRule | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
    ```
2. Display detailed information for a specific rule:
    ```powershell
    Get-NetFirewallRule -Name "rulename" | Format-List *
    ```
3. List firewall profiles and their settings:
    ```powershell
    Get-NetFirewallProfile | Format-Table -AutoSize
    ```

**Expected Output**: Information about all firewall rules and details of specific rules.

### Exercise 10: Investigating Network Sessions

**Objective**: Use PowerShell to list and investigate network sessions on the system.

1. List all active SMB mappings:
    ```powershell
    Get-SmbMapping | Format-Table -AutoSize
    ```
2. Display detailed information for a specific SMB mapping:
    ```powershell
    Get-SmbMapping -Path "path" | Format-List *
    ```
3. List active SMB connections:
    ```powershell
    Get-SmbConnection | Format-Table -AutoSize
    ```

**Expected Output**: Information about all active SMB mappings and connections.

### Exercise 11: Analyzing Log Entries

**Objective**: Use PowerShell to analyze Windows event logs for recent activity.

1. List all event logs:
    ```powershell
    Get-EventLog -List | Format-Table -AutoSize
    ```
2. Display recent events from the System log:
    ```powershell
    Get-EventLog -LogName System -After (Get-Date).AddHours(-2) | Format-Table -AutoSize
    ```
3. Search for specific events containing a keyword:
    ```powershell
    Get-EventLog -LogName System -After (Get-Date).AddHours(-2) | Where-Object { $_.Message -like "*keyword*" } | Format-Table -AutoSize
    ```

**Expected Output**: Information about recent events from the System log and specific events containing a keyword.

## Conclusion

By completing these exercises, you have gained advanced skills in using PowerShell for Windows forensics and incident response. You have learned to investigate user accounts, processes, services, scheduled tasks, registry entries, internet connections, file shares, files, firewall settings, sessions, and log entries. These skills are essential for conducting comprehensive forensic investigations and responding to security incidents effectively.
