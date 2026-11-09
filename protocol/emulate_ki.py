#!/usr/bin/env python3
"""
emulate_ki.py — Master-Key KI + Session-Keys aus GoodixMocSensorAdapter.dll per Emulation.

FUN_180034be0 baut den 32-Byte-Master KI aus obfuskierten Konstanten (bit-rotierte
"Goodix"-Bytes durch AES/HMAC/CRC mit hartcodierten Schluesseln). KI ist damit eine
FESTE Konstante. Statt sie nachzubauen, fuehren wir die Original-Funktionen mit
Unicorn aus:

  1. FUN_180034be0(buf)              -> 32-Byte KI
  2. FUN_1800325d0(KI, 32, out, 48)  -> AES-Key(16) + MAC-Key(32)  (SP 800-108 KDF)

Die gesamte importierte CRT (malloc/calloc/HeapAlloc/free/...) wird ueber eine
gehookte Trampolin-Seite emuliert. Danach Verifikation gegen die Captures.

    sudo pacman -S python-unicorn        (CachyOS/Arch)
    GOODIX_SENSOR_ADAPTER_DLL=/path/to/GoodixMocSensorAdapter.dll python3 protocol/emulate_ki.py
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "re_tools"))

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    print("FEHLER: Unicorn fehlt.  sudo pacman -S python-unicorn")
    sys.exit(1)

from pe import PE

DLL = os.environ.get("GOODIX_SENSOR_ADAPTER_DLL", os.path.join(ROOT, "windows_binaries", "GoodixMocSensorAdapter.dll"))
IMAGE_BASE = 0x180000000
FUN_MASTER = 0x180034be0    # fuellt KI[0:16]
FUN_MASTER2 = 0x180033960   # fuellt KI[16:32] (auf dem Stack direkt hinter local_c0)
FUN_KDF    = 0x1800325d0

STACK_BASE = 0x200000000
STACK_SIZE = 0x200000
HEAP_BASE  = 0x300000000
HEAP_SIZE  = 0x2000000
SCRATCH    = 0x400000000
TRAMP      = 0x500000000     # Trampolin-Seite fuer Import-Stubs
RET_ADDR   = 0x600000000     # Ruecksprung-Sentinel (gemappt)

PAGE = 0x1000
def align_up(x, a=PAGE): return (x + a - 1) & ~(a - 1)


def parse_imports(pe):
    d = pe.d
    e = struct.unpack_from("<I", d, 0x3c)[0]
    ddir = e + 4 + 20 + 112
    imp_rva = struct.unpack_from("<I", d, ddir + 8)[0]
    o = pe.rva2off(imp_rva)
    out = []   # (iat_va, name)
    while True:
        oft, ts, fw, name_rva, first = struct.unpack_from("<IIIII", d, o)
        if name_rva == 0:
            break
        thunk = oft or first
        to = pe.rva2off(thunk)
        k = 0
        while True:
            v = struct.unpack_from("<Q", d, to)[0]
            if v == 0:
                break
            if not (v >> 63):
                ho = pe.rva2off(v & 0x7fffffff)
                nm = d[ho + 2:d.index(b"\0", ho + 2)].decode("latin1")
                out.append((pe.image_base + first + k, nm))
            to += 8
            k += 8
        o += 20
    return out


class Emu:
    def __init__(self):
        self.pe = PE(DLL)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self._map_image()
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)
        self.uc.mem_map(SCRATCH, 0x10000)
        self.uc.mem_map(TRAMP, PAGE)
        self.uc.mem_map(RET_ADDR, PAGE)
        self.uc.mem_write(IMAGE_BASE + 0x56738, b"\x00" * 8)   # security cookie = 0
        self.heap_ptr = HEAP_BASE
        self.fake_heap = 0x11110000
        self.stubs = {}          # sentinel_addr -> name
        self._redirect_iat()
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        self.last_fault = None

    def _map_image(self):
        d = self.pe.d
        top = max(va + max(vs, rs) for _, va, vs, rw, rs, _ in self.pe.secs)
        self.uc.mem_map(IMAGE_BASE, align_up(top))
        self.uc.mem_write(IMAGE_BASE, d[:0x400])
        for n, va, vs, rw, rs, ch in self.pe.secs:
            raw = d[rw:rw + rs]
            if raw:
                self.uc.mem_write(IMAGE_BASE + va, raw)

    def _redirect_iat(self):
        imports = parse_imports(self.pe)
        self.uc.mem_write(TRAMP, b"\xc3" * PAGE)   # ret an jeder Stelle (Fallback)
        for i, (iat_va, name) in enumerate(imports):
            sentinel = TRAMP + i * 8
            self.stubs[sentinel] = name
            self.uc.mem_write(iat_va, struct.pack("<Q", sentinel))

    # ---- Import-Emulation ----
    def _alloc(self, n, zero=True):
        n = (n + 0xf) & ~0xf
        p = self.heap_ptr
        self.heap_ptr += n + 0x10
        if zero:
            self.uc.mem_write(p, b"\x00" * n)
        return p

    def _on_code(self, uc, addr, size, ud):
        name = self.stubs.get(addr)
        if name is None:
            return
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        r8 = uc.reg_read(UC_X86_REG_R8)
        if name in ("malloc",):
            uc.reg_write(UC_X86_REG_RAX, self._alloc(rcx))
        elif name == "calloc":
            uc.reg_write(UC_X86_REG_RAX, self._alloc(rcx * rdx))
        elif name == "realloc":
            uc.reg_write(UC_X86_REG_RAX, self._alloc(rdx))
        elif name == "HeapAlloc":
            uc.reg_write(UC_X86_REG_RAX, self._alloc(r8))
        elif name == "GetProcessHeap":
            uc.reg_write(UC_X86_REG_RAX, self.fake_heap)
        elif name in ("free", "HeapFree"):
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif name == "CryptGenRandom":
            # CryptGenRandom(hProv, dwLen=rdx, pbBuffer=r8): deterministisch fuellen
            uc.mem_write(r8, bytes((i * 7 + 1) & 0xff for i in range(rdx)))
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif name in ("EnterCriticalSection", "LeaveCriticalSection",
                      "InitializeCriticalSection", "DeleteCriticalSection",
                      "InitializeCriticalSectionEx"):
            uc.reg_write(UC_X86_REG_RAX, 1)
        else:
            uc.reg_write(UC_X86_REG_RAX, 0)   # generisch: 0 zurueck
        self._ret(uc)

    def _on_unmapped(self, uc, access, address, size, value, ud):
        self.last_fault = address
        rip = uc.reg_read(UC_X86_REG_RIP)
        print("   [!] unmapped access @ 0x%x (RIP 0x%x, size %d, type %d)"
              % (address, rip, size, access))
        return False   # Emulation stoppen

    def _ret(self, uc):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def call(self, func, args, ret_size, ret_ptr):
        uc = self.uc
        rsp = STACK_BASE + STACK_SIZE - 0x1000
        rsp &= ~0xF
        rsp -= 8
        uc.mem_write(rsp, struct.pack("<Q", RET_ADDR))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        for i, a in enumerate(args[:4]):
            uc.reg_write([UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9][i], a)
        uc.emu_start(func, RET_ADDR, timeout=10 * 1000000, count=0)
        return bytes(uc.mem_read(ret_ptr, ret_size))


def sp800_108(ki, L=48):
    import hashlib, hmac
    label, context = b"kgoodwixg\x00", b"kaelrgnoerlithm"
    out, i = b"", 1
    while len(out) < L:
        msg = struct.pack(">I", i) + label + context + struct.pack(">I", L * 8)
        out += hmac.new(ki, msg, hashlib.sha256).digest()
        i += 1
    return out[:L]


def main():
    if not os.path.exists(DLL):
        print("FEHLER: %s fehlt" % DLL); return 1
    emu = Emu()

    print("== 1. KI = FUN_180034be0 || FUN_180033960 (je 16 B, Stack-benachbart) ==")
    try:
        emu.call(FUN_MASTER,  [SCRATCH],      16, SCRATCH)        # KI[0:16]
        emu.call(FUN_MASTER2, [SCRATCH + 16], 16, SCRATCH + 16)   # KI[16:32]
        ki = bytes(emu.uc.mem_read(SCRATCH, 32))
    except UcError as e:
        print("   Emulationsfehler:", e); return 1
    print("   KI[0:16]  (FUN_180034be0): %s" % ki[:16].hex())
    print("   KI[16:32] (FUN_180033960): %s" % ki[16:].hex())
    print("   KI: %s" % ki.hex())

    print("\n== 2. FUN_1800325d0 emulieren -> Session-Keys ==")
    emu.uc.mem_write(SCRATCH + 0x100, ki)
    try:
        kb = emu.call(FUN_KDF, [SCRATCH + 0x100, 0x20, SCRATCH + 0x200, 0x30],
                      0x30, SCRATCH + 0x200)
    except UcError as e:
        print("   Emulationsfehler KDF:", e)
        kb = None
    if kb:
        aes_key, mac_key = kb[:16], kb[16:48]
        print("   AES-128-Key: %s" % aes_key.hex())
        print("   HMAC-Key:    %s" % mac_key.hex())
        ref = sp800_108(ki)
        print("   Python-KDF stimmt mit Emulator ueberein:", ref == kb)
    else:
        kb = sp800_108(ki)
        aes_key, mac_key = kb[:16], kb[16:48]
        print("   (KDF via Python-Nachbau)")
        print("   AES-128-Key: %s" % aes_key.hex())
        print("   HMAC-Key:    %s" % mac_key.hex())

    print("\n== 3. Verifikation gegen die Captures ==")
    try:
        sys.path.insert(0, os.path.join(ROOT, "scratch"))
        import pcap_crypto as P
        msgs = P.all_messages()
        pad, macok, pts = P.try_key(aes_key, msgs, mac_key=mac_key, verbose=False)
        print("   %d Nachrichten: Padding-OK %d, HMAC-OK %d" % (len(msgs), pad, macok))
        if macok > len(msgs) * 0.3 or pad > len(msgs) * 0.5:
            print("\n   *** TREFFER — Session-Krypto geknackt! ***")
            for m, pt in pts[:3]:
                print("     %s: %s" % (m, pt[:48].hex()))
        else:
            print("   Kein Treffer — bitte KI-Hex hier melden, dann prüfe ich die KDF-Details.")
    except Exception as e:
        print("   (Verifikation uebersprungen: %s)" % e)
        print("   Manuell:  python3 scratch/pcap_crypto.py --key %s" % aes_key.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
