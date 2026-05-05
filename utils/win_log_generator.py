import random
import uuid
import json
from datetime import datetime, timedelta
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom
import os

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
NUM_WINDOWS_EVENTS = 50
NUM_SYSMON_EVENTS  = 50
OUTPUT_DIR         = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────────────────
# FAKE DATA POOLS
# ─────────────────────────────────────────
COMPUTERS    = ["WORKSTATION-01", "DC-CORP-01", "FILESERVER-02", "LAPTOP-HR-05", "DEVBOX-JOHN"]
DOMAINS      = ["CORP", "ACME", "INTERNAL", "WORKGROUP"]
USERS        = ["jsmith", "adavis", "mwilson", "administrator", "svc_backup", "guest"]
PROCESSES    = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\wscript.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Users\Public\malware.exe",
    r"C:\Windows\Temp\dropper.exe",
    r"C:\Program Files\SomeApp\app.exe",
    r"C:\Windows\System32\net.exe",
    r"C:\Windows\System32\mshta.exe",
]
PARENT_PROCESSES = [
    r"C:\Windows\System32\explorer.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\wininit.exe",
]
IP_POOL = [
    "192.168.1.10", "10.0.0.5", "172.16.0.22",
    "45.33.32.156", "185.220.101.5", "8.8.8.8",
    "203.0.113.42", "198.51.100.7"
]
PORTS = [80, 443, 445, 3389, 4444, 8080, 1337, 22, 53, 135]
HASHES = [lambda: "SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex[:32]]

# Windows Security Event ID map
WIN_SECURITY_EVENTS = {
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4648: "A logon was attempted using explicit credentials",
    4656: "A handle to an object was requested",
    4688: "A new process has been created",
    4689: "A process has exited",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4732: "A member was added to a security-enabled local group",
    4776: "The computer attempted to validate credentials for an account",
}
WIN_SYSTEM_EVENTS = {
    7045: "A new service was installed in the system",
    7036: "The service entered the stopped/running state",
    1102: "The audit log was cleared",
}
WIN_APP_EVENTS = {
    1000: "Application Error",
    1001: "Windows Error Reporting",
}

# Sysmon Event ID map
SYSMON_EVENTS = {
    1:  "Process Create",
    3:  "Network Connect",
    7:  "Image Loaded",
    8:  "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent (Object create and delete)",
    13: "RegistryEvent (Value Set)",
    22: "DNSEvent (DNS query)",
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def rand_time(base: datetime, spread_hours: int = 24) -> str:
    delta = timedelta(seconds=random.randint(0, spread_hours * 3600))
    return (base - delta).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "000Z"

def rand_guid() -> str:
    return "{" + str(uuid.uuid4()).upper() + "}"

def rand_hash() -> str:
    return "SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex[:32]

def rand_sid() -> str:
    return f"S-1-5-21-{random.randint(1000000000,9999999999)}-{random.randint(100000000,999999999)}-{random.randint(100000000,999999999)}-{random.randint(1000,9999)}"

def rand_pid() -> str:
    return str(random.randint(100, 65000))

def prettify(elem) -> str:
    rough = tostring(elem, encoding="unicode")
    return minidom.parseString(rough).toprettyxml(indent="  ")


# ─────────────────────────────────────────
# WINDOWS EVENT BUILDER
# ─────────────────────────────────────────
def build_system_block(parent, event_id: int, channel: str, provider: str, record_id: int, ts: str):
    sys = SubElement(parent, "System")
    prov = SubElement(sys, "Provider")
    prov.set("Name", provider)
    prov.set("Guid", rand_guid())
    eid = SubElement(sys, "EventID")
    eid.text = str(event_id)
    SubElement(sys, "Version").text = "0"
    SubElement(sys, "Level").text = "4"
    SubElement(sys, "Task").text   = "0"
    SubElement(sys, "Opcode").text = "0"
    SubElement(sys, "Keywords").text = "0x8020000000000000"
    tc = SubElement(sys, "TimeCreated")
    tc.set("SystemTime", ts)
    SubElement(sys, "EventRecordID").text = str(record_id)
    SubElement(sys, "Correlation")
    ex = SubElement(sys, "Execution")
    ex.set("ProcessID", rand_pid())
    ex.set("ThreadID",  rand_pid())
    SubElement(sys, "Channel").text  = channel
    computer = random.choice(COMPUTERS)
    SubElement(sys, "Computer").text = computer
    SubElement(sys, "Security")
    return computer


def build_windows_event(event_id: int, record_id: int, base_time: datetime) -> dict:
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    root = Element("Event")
    root.set("xmlns", ns)
    ts = rand_time(base_time)
    user   = random.choice(USERS)
    domain = random.choice(DOMAINS)
    proc   = random.choice(PROCESSES)
    pid    = rand_pid()

    if event_id in WIN_SECURITY_EVENTS:
        channel  = "Security"
        provider = "Microsoft-Windows-Security-Auditing"
    elif event_id in WIN_SYSTEM_EVENTS:
        channel  = "System"
        provider = "Service Control Manager"
    else:
        channel  = "Application"
        provider = "Application Error"

    computer = build_system_block(root, event_id, channel, provider, record_id, ts)

    ed = SubElement(root, "EventData")

    if event_id == 4624:
        fields = {
            "SubjectUserSid": rand_sid(), "SubjectUserName": user, "SubjectDomainName": domain,
            "TargetUserName": random.choice(USERS), "TargetDomainName": domain,
            "LogonType": str(random.choice([2, 3, 7, 10])),
            "ProcessName": proc, "IpAddress": random.choice(IP_POOL),
            "IpPort": str(random.choice(PORTS))
        }
    elif event_id == 4625:
        fields = {
            "SubjectUserName": user, "SubjectDomainName": domain,
            "TargetUserName": random.choice(USERS), "LogonType": str(random.choice([2, 3])),
            "FailureReason": "%%2313", "Status": "0xC000006D", "SubStatus": "0xC000006A",
            "IpAddress": random.choice(IP_POOL), "IpPort": str(random.choice(PORTS))
        }
    elif event_id == 4688:
        fields = {
            "SubjectUserName": user, "SubjectDomainName": domain,
            "NewProcessName": proc, "NewProcessId": hex(int(pid)),
            "ParentProcessName": random.choice(PARENT_PROCESSES),
            "CommandLine": proc + " -ExecutionPolicy Bypass -File C:\\temp\\script.ps1",
            "TokenElevationType": "%%1937"
        }
    elif event_id == 4698:
        fields = {
            "SubjectUserName": user, "SubjectDomainName": domain,
            "TaskName": r"\Microsoft\Windows\SuspiciousTask",
            "TaskContent": "<Actions><Exec><Command>" + proc + "</Command></Exec></Actions>"
        }
    elif event_id == 4720:
        fields = {
            "SubjectUserName": user, "SubjectDomainName": domain,
            "TargetUserName": "newuser_" + str(random.randint(100, 999)),
            "TargetSid": rand_sid()
        }
    elif event_id == 7045:
        fields = {
            "ServiceName": "SuspiciousSvc_" + str(random.randint(10, 99)),
            "ImagePath": proc, "ServiceType": "User Mode Service",
            "StartType": "Auto Start", "AccountName": "LocalSystem"
        }
    else:
        fields = {
            "SubjectUserName": user, "SubjectDomainName": domain,
            "ProcessName": proc, "ProcessId": pid
        }

    for name, value in fields.items():
        d = SubElement(ed, "Data")
        d.set("Name", name)
        d.text = value

    return {
        "xml": prettify(root),
        "json": {
            "EventID": event_id, "Channel": channel, "Computer": computer,
            "TimeCreated": ts, "RecordID": record_id,
            "User": user, "Domain": domain, "EventData": fields
        }
    }


# ─────────────────────────────────────────
# SYSMON EVENT BUILDER
# ─────────────────────────────────────────
def build_sysmon_event(event_id: int, record_id: int, base_time: datetime) -> dict:
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    root = Element("Event")
    root.set("xmlns", ns)
    ts       = rand_time(base_time)
    proc     = random.choice(PROCESSES)
    parent   = random.choice(PARENT_PROCESSES)
    user     = random.choice(USERS)
    domain   = random.choice(DOMAINS)
    src_ip   = random.choice(IP_POOL)
    dst_ip   = random.choice(IP_POOL)
    src_port = str(random.choice(PORTS))
    dst_port = str(random.choice(PORTS))
    pid      = rand_pid()
    guid     = rand_guid()
    hsh      = rand_hash()

    computer = build_system_block(root, event_id, "Microsoft-Windows-Sysmon/Operational",
                                  "Microsoft-Windows-Sysmon", record_id, ts)

    ed = SubElement(root, "EventData")

    def data(name, val):
        d = SubElement(ed, "Data")
        d.set("Name", name)
        d.text = val

    if event_id == 1:  # ProcessCreate
        data("RuleName", "-")
        data("UtcTime", ts)
        data("ProcessGuid", guid)
        data("ProcessId", pid)
        data("Image", proc)
        data("FileVersion", "10.0.19041.1")
        data("Description", "Windows Command Processor")
        data("Product", "Microsoft Windows")
        data("Company", "Microsoft Corporation")
        data("OriginalFileName", proc.split("\\")[-1])
        data("CommandLine", proc + " /c whoami")
        data("CurrentDirectory", r"C:\Windows\system32\\")
        data("User", domain + "\\" + user)
        data("LogonGuid", rand_guid())
        data("LogonId", hex(random.randint(10000, 99999)))
        data("TerminalSessionId", "1")
        data("IntegrityLevel", random.choice(["High", "Medium", "System"]))
        data("Hashes", hsh)
        data("ParentProcessGuid", rand_guid())
        data("ParentProcessId", rand_pid())
        data("ParentImage", parent)
        data("ParentCommandLine", parent)
        data("ParentUser", domain + "\\" + random.choice(USERS))
        fields = {"Image": proc, "CommandLine": proc + " /c whoami", "ParentImage": parent,
                  "User": user, "Hashes": hsh}

    elif event_id == 3:  # NetworkConnect
        data("RuleName", "-")
        data("UtcTime", ts)
        data("ProcessGuid", guid)
        data("ProcessId", pid)
        data("Image", proc)
        data("User", domain + "\\" + user)
        data("Protocol", random.choice(["tcp", "udp"]))
        data("Initiated", "true")
        data("SourceIsIpv6", "false")
        data("SourceIp", src_ip)
        data("SourceHostname", random.choice(COMPUTERS))
        data("SourcePort", src_port)
        data("DestinationIsIpv6", "false")
        data("DestinationIp", dst_ip)
        data("DestinationHostname", "")
        data("DestinationPort", dst_port)
        data("DestinationPortName", "-")
        fields = {"Image": proc, "SourceIp": src_ip, "DestinationIp": dst_ip,
                  "DestinationPort": dst_port, "User": user}

    elif event_id == 8:  # CreateRemoteThread
        data("UtcTime", ts)
        data("SourceProcessGuid", guid)
        data("SourceProcessId", pid)
        data("SourceImage", proc)
        data("TargetProcessGuid", rand_guid())
        data("TargetProcessId", rand_pid())
        data("TargetImage", random.choice(PROCESSES))
        data("NewThreadId", str(random.randint(1000, 9999)))
        data("StartAddress", hex(random.randint(0x10000000, 0x7FFFFFFF)))
        data("StartModule", proc)
        data("StartFunction", "-")
        fields = {"SourceImage": proc, "TargetImage": random.choice(PROCESSES)}

    elif event_id == 10:  # ProcessAccess
        data("UtcTime", ts)
        data("SourceProcessGuid", guid)
        data("SourceProcessId", pid)
        data("SourceThreadId", rand_pid())
        data("SourceImage", proc)
        data("TargetProcessGuid", rand_guid())
        data("TargetProcessId", rand_pid())
        data("TargetImage", r"C:\Windows\System32\lsass.exe")
        data("GrantedAccess", "0x1010")
        data("CallTrace", r"C:\Windows\SYSTEM32\ntdll.dll")
        fields = {"SourceImage": proc, "TargetImage": r"C:\Windows\System32\lsass.exe",
                  "GrantedAccess": "0x1010"}

    elif event_id == 11:  # FileCreate
        data("UtcTime", ts)
        data("ProcessGuid", guid)
        data("ProcessId", pid)
        data("Image", proc)
        data("TargetFilename", r"C:\Users\Public\Downloads\payload_" + str(random.randint(100,999)) + ".exe")
        data("CreationUtcTime", ts)
        data("User", domain + "\\" + user)
        fields = {"Image": proc, "TargetFilename": r"C:\Users\Public\Downloads\payload.exe", "User": user}

    elif event_id == 22:  # DNS Query
        domains_list = ["google.com", "evil-c2.ru", "malware-domain.xyz",
                        "pastebin.com", "update.microsoft.com", "raw.githubusercontent.com"]
        queried = random.choice(domains_list)
        data("UtcTime", ts)
        data("ProcessGuid", guid)
        data("ProcessId", pid)
        data("QueryName", queried)
        data("QueryStatus", "0")
        data("QueryResults", dst_ip)
        data("Image", proc)
        data("User", domain + "\\" + user)
        fields = {"Image": proc, "QueryName": queried, "QueryResults": dst_ip}

    else:  # Generic fallback
        data("UtcTime", ts)
        data("ProcessGuid", guid)
        data("ProcessId", pid)
        data("Image", proc)
        data("User", domain + "\\" + user)
        fields = {"Image": proc, "User": user}

    return {
        "xml": prettify(root),
        "json": {
            "EventID": event_id, "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": computer, "TimeCreated": ts, "RecordID": record_id,
            "Description": SYSMON_EVENTS.get(event_id, "Unknown"),
            "EventData": fields
        }
    }


def generate_windows_security_logs(n=10):
    all_windows_json = []
    base_time = datetime.utcnow()
    win_event_ids    = list(WIN_SECURITY_EVENTS.keys()) + list(WIN_SYSTEM_EVENTS.keys()) + list(WIN_APP_EVENTS.keys())
    sysmon_event_ids = list(SYSMON_EVENTS.keys())    
    for i in range(n):
        eid    = random.choice(win_event_ids)
        result = build_windows_event(eid, 1000 + i, base_time)
        all_windows_json.append(result["json"])

    return all_windows_json

def generate_windows_sysmon_logs(n=10):
    all_sysmon_json  = []
    base_time = datetime.utcnow()
    sysmon_event_ids = list(SYSMON_EVENTS.keys())
    for i in range(n):
        eid    = random.choice(sysmon_event_ids)
        result = build_sysmon_event(eid, 2000 + i, base_time)
        all_sysmon_json.append(result["json"])    

    return all_sysmon_json

# ─────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────
def generate_logs():
    base_time = datetime.utcnow()
    win_event_ids    = list(WIN_SECURITY_EVENTS.keys()) + list(WIN_SYSTEM_EVENTS.keys()) + list(WIN_APP_EVENTS.keys())
    sysmon_event_ids = list(SYSMON_EVENTS.keys())

    all_windows_xml  = []
    all_windows_json = []
    all_sysmon_xml   = []
    all_sysmon_json  = []

    for i in range(NUM_WINDOWS_EVENTS):
        eid    = random.choice(win_event_ids)
        result = build_windows_event(eid, 1000 + i, base_time)
        all_windows_xml.append(result["xml"])
        all_windows_json.append(result["json"])

    for i in range(NUM_SYSMON_EVENTS):
        eid    = random.choice(sysmon_event_ids)
        result = build_sysmon_event(eid, 2000 + i, base_time)
        all_sysmon_xml.append(result["xml"])
        all_sysmon_json.append(result["json"])

    # Write Windows Events XML
    win_xml_path = os.path.join(OUTPUT_DIR, "windows_events.xml")
    with open(win_xml_path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
        for block in all_windows_xml:
            lines = block.split("\n")[1:]  # strip inner <?xml?> header
            f.write("\n".join(lines) + "\n")
        f.write("</Events>")

    # Write Sysmon Events XML
    sys_xml_path = os.path.join(OUTPUT_DIR, "sysmon_events.xml")
    with open(sys_xml_path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
        for block in all_sysmon_xml:
            lines = block.split("\n")[1:]
            f.write("\n".join(lines) + "\n")
        f.write("</Events>")

    # Write JSON
    win_json_path = os.path.join(OUTPUT_DIR, "windows_events.json")
    with open(win_json_path, "w", encoding="utf-8") as f:
        json.dump(all_windows_json, f, indent=2)

    sys_json_path = os.path.join(OUTPUT_DIR, "sysmon_events.json")
    with open(sys_json_path, "w", encoding="utf-8") as f:
        json.dump(all_sysmon_json, f, indent=2)

    print(f"[+] Windows Events  → {win_xml_path} ({NUM_WINDOWS_EVENTS} events)")
    print(f"[+] Sysmon Events   → {sys_xml_path} ({NUM_SYSMON_EVENTS} events)")
    print(f"[+] Windows JSON    → {win_json_path}")
    print(f"[+] Sysmon JSON     → {sys_json_path}")

    # Print sample
    print("\n── Sample Windows Event (JSON) ──")
    print(json.dumps(all_windows_json[0], indent=2))
    print("\n── Sample Sysmon Event (JSON) ──")
    print(json.dumps(all_sysmon_json[0], indent=2))
