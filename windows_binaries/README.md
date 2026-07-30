# Windows Driver Adapter DLLs

Die Binärdateien `GoodixMocSensorAdapter.dll` und `GoodixMocStorageAdapter.dll` sind proprietäre Goodix/OEM-Treiberkomponenten und werden **aus Urheberrechtsgründen** nicht in diesem öffentlichen Repository bereitgestellt.

## So erhältst du die DLLs für eigene Analysen:
1. Lade das offizielle Treiberelement für den Goodix GF3268 (USB ID `27c6:6f94`) herunter.
2. Entpacke den Treiber (z. B. mit `7z` oder Windows Device Manager / Driver Cabinet).
3. Entnimm `GoodixMocSensorAdapter.dll` und `GoodixMocStorageAdapter.dll`.
4. Verwende Ghidra, IDA Pro oder `objdump -d` wie in `HANDOVER_COWORK.md` beschrieben.
