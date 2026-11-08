"""rt-devices' payload: what a streaming workload's own process can reach.

Run as the container's main process, so it holds what the payload holds: the
unit's rlimits, the groups, the seccomp filter and the SELinux type. It
prints one line, RT-DEVICES-RESULT and a JSON object, then sleeps.
"""
import ctypes
import errno
import fcntl
import json
import os
import resource
import select
import struct
import subprocess
import time

R = {}


def name(e):
    return errno.errorcode.get(e.errno, str(e.errno))


def ioc(direction, nr, size):
    return (direction << 30) | (size << 16) | (ord("U") << 8) | nr


UI_DEV_CREATE = ioc(0, 1, 0)
UI_DEV_DESTROY = ioc(0, 2, 0)
UI_DEV_SETUP = ioc(1, 3, 92)
UI_SET_EVBIT = ioc(1, 100, 4)
UI_SET_KEYBIT = ioc(1, 101, 4)
UI_GET_SYSNAME = ioc(2, 44, 64)
EV_SYN, EV_KEY, KEY_A = 0, 1, 30
SYS_SCHED_SETSCHEDULER = 144  # x86_64


def event(kind, code, value):
    return struct.pack("llHHi", 0, 0, kind, code, value)


def process():
    status = open("/proc/self/status").read().splitlines()
    R["seccomp"] = next(s.split()[1] for s in status
                        if s.startswith("Seccomp:"))
    R["label"] = open("/proc/self/attr/current").read().strip("\0\n")
    R["rlimit_nice"] = resource.getrlimit(resource.RLIMIT_NICE)
    R["rlimit_rtprio"] = resource.getrlimit(resource.RLIMIT_RTPRIO)


def scheduling():
    try:
        os.setpriority(os.PRIO_PROCESS, 0, -10)
        R["nice"] = os.getpriority(os.PRIO_PROCESS, 0)
    except OSError as e:
        R["nice"] = name(e)
    try:
        os.setpriority(os.PRIO_PROCESS, 0, 0)
    except OSError:
        pass
    pid = os.fork()
    if pid == 0:
        # The raw syscall: musl's sched_setscheduler() is ENOSYS by design.
        libc = ctypes.CDLL(None, use_errno=True)
        priority = ctypes.c_int(10)
        if libc.syscall(SYS_SCHED_SETSCHEDULER, 0, os.SCHED_RR,
                        ctypes.byref(priority)) == 0:
            os._exit(0)
        os._exit(ctypes.get_errno())
    rc = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    R["rt"] = "ok" if rc == 0 else errno.errorcode.get(rc, str(rc))


def uinput():
    """Make a keyboard, find its node under the live /dev/input, open it once
    udev has given it to `uinput`, and read back a key written to it."""
    try:
        fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
    except OSError as e:
        R["uinput_open"] = name(e)
        return None
    R["uinput_open"] = "ok"
    fcntl.ioctl(fd, UI_SET_EVBIT, EV_KEY)
    fcntl.ioctl(fd, UI_SET_KEYBIT, KEY_A)
    fcntl.ioctl(fd, UI_DEV_SETUP, struct.pack(
        "HHHH80sI", 3, 0x1234, 0x5678, 1, b"rt-devices probe", 0))
    fcntl.ioctl(fd, UI_DEV_CREATE)
    sysname = fcntl.ioctl(fd, UI_GET_SYSNAME, bytes(64)).split(b"\0")[0]
    sysdir = f"/sys/devices/virtual/input/{sysname.decode()}"
    deadline = time.monotonic() + 10
    node = reader = None
    while time.monotonic() < deadline:
        try:
            events = [n for n in os.listdir(sysdir) if n.startswith("event")]
            if events:
                node = events[0]
                reader = os.open(f"/dev/input/{node}",
                                 os.O_RDONLY | os.O_NONBLOCK)
                break
        except OSError as e:
            R["virtual_open"] = name(e)
        time.sleep(0.1)
    R["virtual_node"] = node
    if reader is None:
        os.close(fd)
        return node
    R["virtual_open"] = "ok"
    os.write(fd, event(EV_KEY, KEY_A, 1) + event(EV_SYN, 0, 0))
    size = struct.calcsize("llHHi")
    seen = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and (EV_KEY, KEY_A, 1) not in seen:
        if select.select([reader], [], [], 0.5)[0]:
            data = os.read(reader, size * 16)
            seen += [struct.unpack_from("llHHi", data, i)[2:]
                     for i in range(0, len(data) - size + 1, size)]
    R["key_read_back"] = (EV_KEY, KEY_A, 1) in seen
    os.close(reader)
    fcntl.ioctl(fd, UI_DEV_DESTROY)
    os.close(fd)
    return node


def physical(own):
    """Every event node a real device made: none may open."""
    R["physical"] = {}
    for node in sorted(os.listdir("/dev/input")):
        if not node.startswith("event") or node == own:
            continue
        device = os.path.realpath(f"/sys/class/input/{node}/device")
        if "/devices/virtual/" in device:
            continue
        try:
            os.close(os.open(f"/dev/input/{node}", os.O_RDONLY))
            R["physical"][node] = "ok"
        except OSError as e:
            R["physical"][node] = name(e)


def sound():
    R["snd"] = sorted(os.listdir("/dev/snd")) if os.path.isdir("/dev/snd") else []


def namespaces():
    """What Steam's bwrap does first: a user and mount namespace of its
    own, and a tmpfs mounted and unmounted in it."""
    libc = ctypes.CDLL(None, use_errno=True)
    uid, gid = os.getuid(), os.getgid()
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        step = "unshare"
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
            step = "id maps"
            for path, text in (("/proc/self/setgroups", "deny"),
                               ("/proc/self/uid_map", f"0 {uid} 1"),
                               ("/proc/self/gid_map", f"0 {gid} 1")):
                with open(path, "w") as f:
                    f.write(text)
            for step, call in (
                    ("mount", lambda: libc.mount(b"none", b"/tmp", b"tmpfs",
                                                 0, None)),
                    ("umount2", lambda: libc.umount2(b"/tmp", 0))):
                if call() != 0:
                    raise OSError(ctypes.get_errno(), step)
            out = "ok"
        except OSError as e:
            out = f"{step}: {name(e)}"
        os.write(w, out.encode())
        os._exit(0)
    os.close(w)
    os.waitpid(pid, 0)
    R["namespaces"] = os.read(r, 200).decode()


def elf32_exit(code):
    """An i386 program that makes one 32-bit syscall, exit(code)."""
    base = 0x08048000
    text = b"\xb8\x01\x00\x00\x00\xbb" + struct.pack("<I", code) + b"\xcd\x80"
    size = 52 + 32 + len(text)
    header = (b"\x7fELF\x01\x01\x01" + bytes(9)
              + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, base + 84, 52, 0, 0,
                            52, 32, 1, 0, 0, 0))
    program = struct.pack("<IIIIIIII", 1, 0, base, base, size, size, 5,
                          0x1000)
    return header + program + text


def compat32():
    path = "/tmp/rt-devices-elf32"
    with open(path, "wb") as f:
        f.write(elf32_exit(42))
    os.chmod(path, 0o755)
    R["elf32_rc"] = subprocess.run([path]).returncode


for check in (process, scheduling, sound, namespaces, compat32):
    try:
        check()
    except Exception as e:  # noqa: BLE001 - one check's error is its result
        R[check.__name__ + "_error"] = repr(e)
own = None
try:
    own = uinput()
except Exception as e:  # noqa: BLE001
    R["uinput_error"] = repr(e)
try:
    physical(own)
except Exception as e:  # noqa: BLE001
    R["physical_error"] = repr(e)
print("RT-DEVICES-RESULT " + json.dumps(R), flush=True)
while True:
    time.sleep(3600)
