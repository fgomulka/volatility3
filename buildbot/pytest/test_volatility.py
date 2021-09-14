# volatility3 tests
#

#
# IMPORTS
#

import os
import subprocess
import sys
import shutil
import tempfile
import hashlib
import ntpath
import json

import pytest

#
# HELPER FUNCTIONS
#

def runvol(args):
    volpy = pytest.config.getoption("--volatility", default=None)
    python_cmd = pytest.config.getoption("--python", default="python3")

    cmd = [python_cmd, volpy] + args
    print(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    print("stdout:")
    sys.stdout.write(str(stdout))
    print("")
    print("stderr:")
    sys.stdout.write(str(stderr))
    print("")

    return p.returncode, stdout, stderr

def runvol_plugin(plugin, img, pluginargs=[], globalargs=[]):
    args = globalargs + [
        "--single-location",
        "file:///" + img,
        "-q",
        plugin,
    ] + pluginargs

    return runvol(args)

#
# TESTS
#

# WINDOWS

def test_windows_pslist(image):
    rc, out, err = runvol_plugin("windows.pslist.PsList", image)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0
    assert rc == 0

    rc, out, err = runvol_plugin(
        "windows.pslist.PsList", image, pluginargs=["--pid", "4"])
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.count(b"\n") < 10
    assert rc == 0
    assert rc == 0

def test_windows_psscan(image):
    rc, out, err = runvol_plugin("windows.psscan.PsScan", image)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0
    assert rc == 0

def test_windows_dlllist(image):
    rc, out, err = runvol_plugin("windows.dlllist.DllList", image)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0
    assert rc == 0

def test_windows_modules(image):
    rc, out, err = runvol_plugin("windows.modules.Modules", image)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0
    assert rc == 0

def test_windows_hivelist(image):
    rc, out, err = runvol_plugin("windows.registry.hivelist.HiveList", image)
    out = out.lower()

    not_xp = out.find(b"\\systemroot\\system32\\config\\software")
    if not_xp == -1:
        assert out.find(b"\\device\\harddiskvolume1\\windows\\system32\\config\\software") != -1

    assert out.count(b"\n") > 10
    assert rc == 0

def test_windows_dumpfiles(image):

    json_file = open('known_files.json')

    known_files = json.load(json_file)

    failed_chksms = 0

    if sys.platform == 'win32':
        file_name = ntpath.basename(image)
    else:
        file_name = os.path.basename(image)

    try:
        for addr in known_files["windows_dumpfiles"][file_name]:

            path = tempfile.mkdtemp()

            rc, out, err = runvol_plugin("windows.dumpfiles.DumpFiles", image, globalargs=["-o", path], pluginargs=["--virtaddr", addr])

            for file in os.listdir(path):
                fp = open(os.path.join(path, file), "rb")
                if hashlib.md5(fp.read()).hexdigest() not in known_files["windows_dumpfiles"][file_name][addr]:
                    failed_chksms += 1
                fp.close()

            shutil.rmtree(path)

        json_file.close()

        assert failed_chksms == 0
        assert rc == 0
    except Exception as e:
        json_file.close()
        print("Key Error raised on " + str(e))
        assert False

def test_windows_handles(image):
    rc, out, err = runvol_plugin(
        "windows.handles.Handles", image, pluginargs=["--pid", "4"])

    assert out.find(b"System Pid 4") != -1
    assert out.find(b"MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER\\MEMORY MANAGEMENT\\PREFETCHPARAMETERS") != -1
    assert out.find(b"MACHINE\\SYSTEM\\SETUP") != -1
    assert out.count(b"\n") > 500
    assert rc == 0

def test_windows_svcscan(image):
    rc, out, err = runvol_plugin("windows.svcscan.SvcScan", image)

    assert out.find(b"Microsoft ACPI Driver") != -1
    assert out.count(b"\n") > 250
    assert rc == 0

def test_windows_privileges(image):
    rc, out, err = runvol_plugin(
        "windows.privileges.Privs", image, pluginargs=["--pid", "4"])

    assert out.find(b"SeCreateTokenPrivilege") != -1
    assert out.find(b"SeCreateGlobalPrivilege") != -1
    assert out.find(b"SeAssignPrimaryTokenPrivilege") != -1
    assert out.count(b"\n") > 20
    assert rc == 0

def test_windows_getsids(image):
    rc, out, err = runvol_plugin(
        "windows.getsids.GetSIDs", image, pluginargs=["--pid", "4"])

    assert out.find(b"Local System") != -1
    assert out.find(b"Administrators") != -1
    assert out.find(b"Everyone") != -1
    assert out.find(b"Authenticated Users") != -1
    assert rc == 0

def test_windows_envars(image):
    rc, out, err = runvol_plugin("windows.envars.Envars", image)

    assert out.find(b"PATH") != -1
    assert out.find(b"PROCESSOR_ARCHITECTURE") != -1
    assert out.find(b"USERNAME") != -1
    assert out.find(b"SystemRoot") != -1
    assert out.find(b"CommonProgramFiles") != -1
    assert out.count(b"\n") > 500
    assert rc == 0

def test_windows_callbacks(image):
    rc, out, err = runvol_plugin("windows.callbacks.Callbacks", image)

    assert out.find(b"PspCreateProcessNotifyRoutine") != -1
    assert out.find(b"KeBugCheckCallbackListHead") != -1
    assert out.find(b"KeBugCheckReasonCallbackListHead") != -1
    assert out.count(b"KeBugCheckReasonCallbackListHead	") > 5
    assert rc == 0

# LINUX

def test_linux_pslist(image):
    rc, out, err = runvol_plugin("linux.pslist.PsList", image)
    out = out.lower()

    assert ((out.find(b"init") != -1) or (out.find(b"systemd") != -1))
    assert out.find(b"watchdog") != -1
    assert out.count(b"\n") > 10
    assert rc == 0

def test_linux_check_idt(image):
    rc, out, err = runvol_plugin("linux.check_idt.Check_idt", image)
    out = out.lower()

    assert out.count(b"__kernel__") >= 10
    assert out.count(b"\n") > 10
    assert rc == 0

def test_linux_check_syscall(image):
    rc, out, err = runvol_plugin("linux.check_syscall.Check_syscall", image)
    out = out.lower()

    assert out.find(b"sys_close") != -1
    assert out.find(b"sys_open") != -1
    assert out.count(b"\n") > 100
    assert rc == 0

def test_linux_lsmod(image):
    rc, out, err = runvol_plugin("linux.lsmod.Lsmod", image)
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0

def test_linux_lsof(image):
    rc, out, err = runvol_plugin("linux.lsof.Lsof", image)
    out = out.lower()

    assert out.count(b"socket:") >= 10
    assert out.count(b"\n") > 35
    assert rc == 0

def test_linux_proc_maps(image):
    rc, out, err = runvol_plugin("linux.proc.Maps", image)
    out = out.lower()

    assert out.count(b"anonymous mapping") >= 10
    assert out.count(b"\n") > 100
    assert rc == 0

def test_linux_tty_check(image):
    rc, out, err = runvol_plugin("linux.tty_check.tty_check", image)
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") >= 5
    assert rc == 0

# MAC

def test_mac_pslist(image):
    rc, out, err = runvol_plugin("mac.pslist.PsList", image)
    out = out.lower()

    assert ((out.find(b"kernel_task") != -1) or (out.find(b"launchd") != -1))
    assert out.count(b"\n") > 10
    assert rc == 0

def test_mac_check_syscall(image):
    rc, out, err = runvol_plugin("mac.check_syscall.Check_syscall", image)
    out = out.lower()

    assert out.find(b"chmod") != -1
    assert out.find(b"chown") != -1
    assert out.find(b"nosys") != -1
    assert out.count(b"\n") > 100
    assert rc == 0

def test_mac_check_sysctl(image):
    rc, out, err = runvol_plugin("mac.check_sysctl.Check_sysctl", image)
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") > 250
    assert rc == 0

def test_mac_check_trap_table(image):
    rc, out, err = runvol_plugin("mac.check_trap_table.Check_trap_table", image)
    out = out.lower()

    assert out.count(b"kern_invalid") >= 10
    assert out.count(b"\n") > 50
    assert rc == 0

def test_mac_ifconfig(image):
    rc, out, err = runvol_plugin("mac.ifconfig.Ifconfig", image)
    out = out.lower()

    assert out.find(b"127.0.0.1") != -1
    assert out.find(b"false") != -1
    assert out.count(b"\n") > 9
    assert rc == 0

def test_mac_lsmod(image):
    rc, out, err = runvol_plugin("mac.lsmod.Lsmod", image)
    out = out.lower()

    assert out.find(b"com.apple") != -1
    assert out.count(b"\n") > 10
    assert rc == 0

def test_mac_lsof(image):
    rc, out, err = runvol_plugin("mac.lsof.Lsof", image)
    out = out.lower()

    assert out.count(b"\n") > 50
    assert rc == 0

def test_mac_malfind(image):
    rc, out, err = runvol_plugin("mac.malfind.Malfind", image)
    out = out.lower()

    assert out.count(b"\n") > 20
    assert rc == 0

def test_mac_mount(image):
    rc, out, err = runvol_plugin("mac.mount.Mount", image)
    out = out.lower()

    assert out.find(b"/dev") != -1
    assert out.count(b"\n") > 7
    assert rc == 0

def test_mac_netstat(image):
    rc, out, err = runvol_plugin("mac.netstat.Netstat", image)

    assert out.find(b"TCP") != -1
    assert out.find(b"UDP") != -1
    assert out.find(b"UNIX") != -1
    assert out.count(b"\n") > 10
    assert rc == 0

def test_mac_proc_maps(image):
    rc, out, err = runvol_plugin("mac.proc_maps.Maps", image)
    out = out.lower()

    assert out.find(b"[heap]") != -1
    assert out.count(b"\n") > 100
    assert rc == 0

def test_mac_psaux(image):
    rc, out, err = runvol_plugin("mac.psaux.Psaux", image)
    out = out.lower()

    assert out.find(b"executable_path") != -1
    assert out.count(b"\n") > 50
    assert rc == 0

def test_mac_socket_filters(image):
    rc, out, err = runvol_plugin("mac.socket_filters.Socket_filters", image)
    out = out.lower()

    assert out.count(b"\n") > 9
    assert rc == 0

def test_mac_timers(image):
    rc, out, err = runvol_plugin("mac.timers.Timers", image)
    out = out.lower()

    assert out.count(b"\n") > 6
    assert rc == 0

def test_mac_trustedbsd(image):
    rc, out, err = runvol_plugin("mac.trustedbsd.Trustedbsd", image)
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0
