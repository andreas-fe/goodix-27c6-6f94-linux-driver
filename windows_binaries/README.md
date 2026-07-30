# Windows Driver Adapter DLLs

The binaries `GoodixMocSensorAdapter.dll` and `GoodixMocStorageAdapter.dll` are proprietary Goodix/OEM driver components and are **NOT** provided in this public repository for **copyright reasons**.

## How to obtain the DLLs for your own analysis:
1. Download the official Windows driver package for the Goodix GF3268 (USB ID `27c6:6f94`).
2. Extract the driver package (e.g., using `7z` or Windows Device Manager / Driver Cabinet).
3. Extract `GoodixMocSensorAdapter.dll` and `GoodixMocStorageAdapter.dll`.
4. Use Ghidra, IDA Pro or `objdump -d` as described in `HANDOVER_COWORK.md`.
