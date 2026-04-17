/*
 * Custom YARA Rules for Demo 04: Antivirus Analysis
 * These rules detect patterns not covered by standard AV signatures.
 * For educational purposes — demonstrates custom threat detection.
 */

rule Suspicious_Office_Macro {
    meta:
        description = "Detects suspicious VBA macros that spawn shell objects"
        author = "Security Operations Master Class"
        reference = "T1059.005 — Visual Basic"
        severity = "HIGH"
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "CreateObject" nocase
        $s3 = "AutoOpen" nocase
        $s4 = "-enc" nocase
        $s5 = "powershell" nocase
    condition:
        ($s1 or $s2) and ($s3) and ($s4 or $s5)
}

rule LOLBin_CertUtil_Download {
    meta:
        description = "Detects certutil used for file download (LOLBin abuse)"
        author = "Security Operations Master Class"
        reference = "T1105 — Ingress Tool Transfer via LOLBin"
        severity = "HIGH"
    strings:
        $cmd1 = "certutil" nocase
        $opt1 = "-urlcache" nocase
        $opt2 = "-split" nocase
        $opt3 = "-f" nocase
        $http = "http" nocase
    condition:
        $cmd1 and ($opt1 or $opt2) and $http
}

rule LOLBin_MSHTA_Remote {
    meta:
        description = "Detects mshta executing remote HTA (LOLBin)"
        reference = "T1218.005 — Signed Binary Proxy Execution: Mshta"
        severity = "HIGH"
    strings:
        $cmd = "mshta" nocase
        $http = "http" nocase
        $hta = ".hta" nocase
    condition:
        $cmd and ($http or $hta)
}

rule PowerShell_Encoded_Command {
    meta:
        description = "Detects PowerShell with base64-encoded commands"
        reference = "T1059.001 — PowerShell"
        severity = "MEDIUM"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $nop = "-nop" nocase
        $hidden = "-w hidden" nocase
    condition:
        $ps and ($enc1 or $enc2) and ($nop or $hidden)
}

rule Suspicious_IEX_Download {
    meta:
        description = "Detects PowerShell download-and-execute (IEX)"
        reference = "T1059.001 — PowerShell Fileless Execution"
        severity = "HIGH"
    strings:
        $iex1 = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "WebClient" nocase
        $dl3 = "wget" nocase
        $dl4 = "curl" nocase
    condition:
        ($iex1 or $iex2) and ($dl1 or $dl2 or $dl3 or $dl4)
}

rule Base64_Encoded_Payload {
    meta:
        description = "Detects base64-encoded PowerShell or PE content"
        reference = "T1027 — Obfuscated Files"
        severity = "LOW"
    strings:
        // Common base64 headers for Windows executables and PowerShell
        $pe_b64 = "TVqQAA" // "MZ" in base64 (PE header)
        $ps_b64 = "JAB" // "$" in UTF-16LE base64 (common PS start)
        $iex_indicator = "DownloadString" nocase
    condition:
        ($pe_b64 or $ps_b64) and $iex_indicator
}
