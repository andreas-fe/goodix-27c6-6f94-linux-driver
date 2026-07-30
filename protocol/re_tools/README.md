# Offline-RE-Werkzeuge (kein Ghidra/JDK nötig)

Eigenständige PE- und pcapng-Parser für die Analyse von `GoodixMocWbdi.dll`
und der USB-Captures. Nur Standardbibliothek + objdump.

- `pe.py`     — PE64-Parser: Sektionen, RVA↔Offset, `.text`, image_base
- `pdata.py`  — Funktionsgrenzen aus `.pdata` (exakt, 2030 Funktionen), `containing(rva)`
- `xref.py`   — RIP-relative LEA-Xrefs (String-Referenzen finden)
- `pcapng.py` — usbmon/pcapng-Parser → (urb_type, epnum, payload)

## Beispiele
```bash
# Funktion, die eine String-Referenz enthält:
python3 -c "import sys;sys.path.insert(0,'scratch/re_tools');
from pe import PE; from pdata import funcs,containing
pe=PE('windows_driver_binaries/GoodixMocWbdi.dll'); fs=funcs(pe)
tva,_=pe.text(); print(containing(fs, tva+0x3de84))"

# Disassembly einer Funktion:
objdump -D -b pei-x86-64 -m i386:x86-64 \
  --start-address=0x18008edc0 --stop-address=0x18008f529 \
  windows_driver_binaries/GoodixMocWbdi.dll

# Aufrufer einer Funktion (E8-Calls) — siehe Snippet in xref.py
```

## Wichtige Adressen in GoodixMocWbdi.dll (image_base 0x180000000)
- `gf_sha256`-Wrapper:      VA 0x18003b628 (RVA 0x3b628..0x3b879)
- `gf_hmac_sha256`-Wrapper: VA 0x18003dadc (RVA 0x3dadc..0x3e0e9)
- `ProcessPsk` (PSK-Provisionierung): VA 0x18008edc0 (RVA 0x8edc0..0x8f529)
- Suite-String `TLS-PSK-WITH-AES-128-CBC-SHA256`: RVA 0x3b06d2
- mbedtls-Debug-Strings ab RVA 0x3aXXXX (toter Code, Debug aus)

## Nächstes Ziel
Die mbedTLS-Sitzungs-Schlüsselableitung (nutzt mbedtls-eigenes HMAC, nicht den
gf_-Wrapper). Kandidaten: Funktionen, die auf das SSL-Kontext-Struct zugreifen
und `PRF`/`derive_keys` implementieren. Siehe HANDOVER_COWORK.md Abschnitt 19.
