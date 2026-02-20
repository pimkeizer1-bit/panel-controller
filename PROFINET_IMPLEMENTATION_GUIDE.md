# PROFINET IO Controller Implementation Guide

## Purpose

This document describes how to implement a PROFINET IO Controller in Python to control a Siemens ET200SP distributed I/O system. It covers the complete protocol stack from device discovery to cyclic data exchange, including every protocol detail, encoding quirk, and pitfall discovered during development.

**Target audience**: Anyone implementing PROFINET IO communication from scratch (no PLC, no Siemens TIA Portal) using raw sockets and Python.

**Hardware tested**: Siemens ET200SP (IM 155-6 PN BA) with DQ 8x24VDC/0.5A and AI 8xRTD/TC 2-wire HF modules.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Dependencies & Prerequisites](#2-dependencies--prerequisites)
3. [Step 1: DCP Device Discovery](#3-step-1-dcp-device-discovery)
4. [Step 2: EPM Port Discovery](#4-step-2-epm-port-discovery)
5. [Step 3: DCE/RPC Connect Request](#5-step-3-dcerpc-connect-request)
6. [Step 4: Module Parameterization (Write)](#6-step-4-module-parameterization-write)
7. [Step 5: PrmEnd](#7-step-5-prmend)
8. [Step 6: ApplicationReady](#8-step-6-applicationready)
9. [Step 7: Cyclic RTC Data Exchange](#9-step-7-cyclic-rtc-data-exchange)
10. [Step 8: Disconnect / Release](#10-step-8-disconnect--release)
11. [AI Module Configuration (GSDML)](#11-ai-module-configuration-gsdml)
12. [Complete Bug List & Solutions](#12-complete-bug-list--solutions)
13. [Wireshark Analysis Tips](#13-wireshark-analysis-tips)
14. [File Structure](#14-file-structure)

---

## 1. Architecture Overview

### Connection Sequence

```
Controller (PC)                          Device (ET200SP)
     |                                        |
     |--- DCP Identify All (broadcast) ------>|
     |<-- DCP Identify Response --------------|
     |                                        |
     |--- DCP Set IP (unicast to MAC) ------->|
     |<-- DCP Set Response -------------------|
     |                                        |
     |--- EPM Lookup (UDP port 34964) ------->|
     |<-- EPM Response (PNIO port=49156) -----|
     |                                        |
     |--- Connect Request (UDP port 49156) -->|
     |<-- Connect Response -------------------|
     |                                        |
     |--- Write (MultipleWrite) ------------->|
     |<-- Write Response ---------------------|
     |                                        |
     |--- PrmEnd (Control, opnum 4) --------->|
     |<-- PrmEnd Response --------------------|
     |                                        |
     |<-- ApplicationReady (port 34964) ------|  (device initiates!)
     |--- ApplicationReady Response --------->|
     |                                        |
     |=== Cyclic RTC frames (Layer 2) ========|  (128ms cycle)
     |--- Output frame (EtherType 0x8892) --->|
     |<-- Input frame (VLAN + 0x8892) --------|
```

### Protocol Layers

| Layer | Protocol | Transport | Library |
|-------|----------|-----------|---------|
| Discovery | DCP (Discovery and Configuration Protocol) | Raw Ethernet (Layer 2) | `pnio-dcp` |
| Connection | DCE/RPC Connectionless | UDP | Raw sockets |
| Cyclic Data | RTC (Real-Time Cyclic) | Raw Ethernet (EtherType 0x8892) | Scapy |

### Key UUIDs

| UUID | Purpose |
|------|---------|
| `dea00001-6c97-11d1-8271-00a02442df7d` | PNIO Device Interface (for Connect/Write/PrmEnd) |
| `dea00002-6c97-11d1-8271-00a02442df7d` | PNIO Controller Interface (for ApplicationReady) |
| `e1af8308-5d1f-11c9-91a4-08002b14a0fa` | EPM (Endpoint Mapper) Interface |
| `dea00000-6c97-11d1-8271-0001{DeviceID}{VendorID}` | PNIO Object UUID |

---

## 2. Dependencies & Prerequisites

### Python packages

```
pnio-dcp>=1.1.0      # PROFINET DCP discovery & IP assignment
scapy>=2.5.0          # Raw Ethernet frame building/parsing for RTC
PyQt6>=6.5.0          # GUI framework (optional)
psutil>=5.9.0         # Network adapter enumeration (optional)
```

### System requirements

- **Npcap** (Windows) — required by Scapy for raw Ethernet access
- **Administrator privileges** — required for raw socket operations
- **Dedicated Ethernet adapter** — the adapter connecting to the PROFINET device should ideally be on its own subnet (192.168.0.0/24)

### Network setup

- Controller IP: `192.168.0.253` (or any IP on the 192.168.0.0/24 subnet)
- Device IP: assigned via DCP (e.g., `192.168.0.1`)
- Subnet: `255.255.255.0`
- The controller may need a secondary IP added to the adapter: `netsh interface ip add address "Ethernet" 192.168.0.253 255.255.255.0`

---

## 3. Step 1: DCP Device Discovery

DCP operates at Layer 2 (raw Ethernet). Use the `pnio-dcp` library.

```python
from pnio_dcp import DCP

dcp = DCP("Ethernet")  # adapter name
devices = dcp.identify_all(timeout=8)

for device in devices:
    mac = device.MAC
    name = device.name_of_station
    ip = device.IP

# Assign IP to device
dcp.set_ip(mac="4c:e7:05:2e:ef:2c",
           ip="192.168.0.1",
           subnet="255.255.255.0",
           gateway="0.0.0.0",
           store_permanent=False)
```

**Key points:**
- DCP uses EtherType 0x8892 (same as PROFINET RT)
- Scanning takes ~8 seconds (multiple retries)
- IP assignment is temporary by default — device forgets it on power cycle
- The device MAC address discovered here is the **management MAC**, not necessarily the port MAC used for RTC frames

---

## 4. Step 2: EPM Port Discovery

After assigning the device an IP, discover which UDP port the PNIO service listens on.

### EPM Lookup Request

Send a DCE/RPC Endpoint Mapper Lookup (opnum 2) to UDP port **34964** (0x8894).

```
RPC Header (80 bytes):
  - interface_uuid = EPM UUID (e1af8308-...)
  - interface_version = 3
  - operation = 2 (Lookup)
  - flags1 = 0x20 (Idempotent)

Body: EPM Lookup stub containing the PNIO Device Interface UUID
```

### EPM Lookup Response

Parse the response to find the UDP floor entry (protocol ID 0x08) containing the port number.

**Typical result**: Port 49156 (can vary per device/boot).

**Fallback**: If EPM fails, probe ports 49152-49156 with a lightweight RPC ReadImplicit request.

---

## 5. Step 3: DCE/RPC Connect Request

### DCE/RPC Header Format (80 bytes)

This is the most error-prone part. The header format is:

```
Offset  Size  Field                   Encoding
0       1     rpc_vers (4)            Big-endian
1       1     ptype (0=Request)       Big-endian
2       1     flags1                  Big-endian
3       1     flags2                  Big-endian
4       3     drep (10 00 00)         Fixed
7       1     serial_hi               Big-endian
8       16    object_uuid             MIXED-ENDIAN (DCE/RPC format)
24      16    interface_uuid          MIXED-ENDIAN (DCE/RPC format)
40      16    activity_uuid           MIXED-ENDIAN (DCE/RPC format)
56      4     server_boot_time        Little-endian
60      4     interface_version       Little-endian
64      4     sequence_number         Little-endian
68      2     operation               Little-endian
70      2     interface_hint (0xFFFF) Little-endian
72      2     activity_hint (0xFFFF)  Little-endian
74      2     body_length             Little-endian
76      2     fragment_number         Little-endian
78      1     auth_protocol           Big-endian
79      1     serial_lo               Big-endian
```

### CRITICAL: UUID Encoding

**There are TWO different UUID encodings used in PROFINET!**

1. **DCE/RPC mixed-endian** — used ONLY in the 80-byte RPC header:
   - `time_low`: 4 bytes **little-endian**
   - `time_mid`: 2 bytes **little-endian**
   - `time_hi_and_version`: 2 bytes **little-endian**
   - `clock_seq`: 2 bytes big-endian
   - `node`: 6 bytes big-endian

2. **Big-endian** — used in ALL PROFINET block payloads (ARBlockReq, IODWriteReq, IODControlReq, etc.):
   - ALL fields are big-endian

**Getting this wrong causes silent failures or cryptic PNIO errors.**

```python
def uuid_to_bytes_le(u):  # For RPC header
    fields = u.fields
    return (struct.pack("<IHH", fields[0], fields[1], fields[2])
            + struct.pack("!BB", fields[3], fields[4])
            + struct.pack("!Q", fields[5])[2:])

def uuid_to_bytes_be(u):  # For PROFINET blocks
    fields = u.fields
    return (struct.pack("!IHH", fields[0], fields[1], fields[2])
            + struct.pack("!BB", fields[3], fields[4])
            + struct.pack("!Q", fields[5])[2:])
```

### Connect Request Body (NRD payload)

The Connect request body is wrapped in an NDR array:

```
ArgsMaximum (4 bytes, LE)
ArgsLength  (4 bytes, LE)
MaxCount    (4 bytes, LE)
Offset      (4 bytes, LE) = 0
ActualCount (4 bytes, LE)
<blocks>
```

The blocks are (in order):
1. **ARBlockReq** (Application Relation)
2. **IOCRBlockReq** for Input CR (device → controller)
3. **IOCRBlockReq** for Output CR (controller → device)
4. **ExpectedSubmoduleBlockReq** for Slot 0 (DAP)
5. **ExpectedSubmoduleBlockReq** for Slot 1 (DQ)
6. **ExpectedSubmoduleBlockReq** for Slot 2 (AI)
7. **ExpectedSubmoduleBlockReq** for Slot 3 (Server)
8. **AlarmCRBlockReq**

Each block starts with: `BlockType(2) + BlockLength(2) + Version(2) + data`

### ARBlockReq

```
ARType              = 0x0001 (IO Controller AR)
ARUUID              = 00000000-0000-0000-0000-{device_mac}  (big-endian)
SessionKey          = 1
CMInitiatorMacAdd   = controller_mac (6 bytes)
CMInitiatorObjectUUID = dea00000-6c97-11d1-8271-... (big-endian)
ARProperties        = 0x00000011 (Active + PrmServer=CMInitiator)
CMInitiatorActivityTimeoutFactor = 200 (200 * 100ms = 20s)
InitiatorUDPRTPort  = 0x8892
StationNameLength   = len(name)
StationName         = "panel-controller" (ASCII, NOT padded)
```

### IOCRBlockReq

```
IOCRType            = 1 (Input CR) or 2 (Output CR)
IOCRReference       = 1 or 2
LT                  = 0x8892
IOCRProperties      = 0x00000002 (RT_CLASS_2)
DataLength          = 40 (total RTC payload size)
FrameID             = 0xBB80 (Input, proposed) or 0xBB81 (Output, proposed)
SendClockFactor     = 32 (32 * 31.25us = 1ms base)
ReductionRatio      = 128 (send every 128th cycle = 128ms)
Phase               = 1
FrameSendOffset     = 0xFFFFFFFF (best effort)
WatchdogFactor      = 3
DataHoldFactor      = 3
IOCRTagHeader       = 0xC000 (VLAN priority 6)
IOCRMulticastMACAdd = 00:00:00:00:00:00 (unicast)
NumberOfAPIs        = 1
```

Each IOCR contains IODataObjects and IOCS entries mapping submodules to frame offsets:

**Input CR IODataObjects** (what the device sends):
| Slot | Subslot | FrameOffset |
|------|---------|-------------|
| 0x0000 | 0x0001 | 0 (DAP IOPS) |
| 0x0000 | 0x8000 | 1 (Interface IOPS) |
| 0x0000 | 0x8001 | 2 (Port 1 IOPS) |
| 0x0000 | 0x8002 | 3 (Port 2 IOPS) |
| 0x0002 | 0x0001 | 5 (AI data, 16 bytes) |
| 0x0003 | 0x0001 | 22 (Server IOPS) |

**Input CR IOCS** (consumer status for output modules):
| Slot | Subslot | FrameOffset |
|------|---------|-------------|
| 0x0001 | 0x0001 | 4 (DQ IOCS) |

**Output CR IODataObjects** (what we send):
| Slot | Subslot | FrameOffset |
|------|---------|-------------|
| 0x0001 | 0x0001 | 4 (DQ data, 1 byte) |

**Output CR IOCS** (consumer status for input modules):
| Slot | Subslot | FrameOffset |
|------|---------|-------------|
| 0x0000 | 0x0001 | 0 |
| 0x0000 | 0x8000 | 1 |
| 0x0000 | 0x8001 | 2 |
| 0x0000 | 0x8002 | 3 |
| 0x0002 | 0x0001 | 6 |
| 0x0003 | 0x0001 | 7 |

### ExpectedSubmoduleBlockReq

One block per slot. Each contains the module identifier and submodule list:

**Slot 0 — DAP (IM 155-6 PN BA):**
| Subslot | SubmoduleIdent | Type |
|---------|---------------|------|
| 0x0001 | 0x00000002 | No I/O |
| 0x8000 | 0x00008002 | No I/O |
| 0x8001 | 0x0000C000 | No I/O |
| 0x8002 | 0x0000C000 | No I/O |

**Slot 1 — DQ 8x24VDC/0.5A:**
| ModuleIdent | SubmoduleIdent | Output Length |
|-------------|---------------|---------------|
| 0x00004D9C | 0x00000008 | 1 byte |

**Slot 2 — AI 8xRTD/TC 2-wire HF:**
| ModuleIdent | SubmoduleIdent | Input Length |
|-------------|---------------|--------------|
| 0x00004A7F | 0x00000008 | 16 bytes |

**Slot 3 — Server Module:**
| ModuleIdent | SubmoduleIdent | Type |
|-------------|---------------|------|
| 0x00004710 | 0x00000000 | No I/O |

### Connect Response

The device responds with:
- PNIOStatus (4 bytes) — must be `00 00 00 00`
- NDR header (16 bytes)
- AR_BLOCK_RES — confirms AR UUID and session key
- IOCR_BLOCK_RES (x2) — confirms frame IDs:
  - Input CR: frame_id (usually matches proposed 0xBB80)
  - Output CR: frame_id (device assigns, e.g., 0x8000)

**Use the frame IDs from the response, not your proposed values.**

### RPC flags

| Operation | flags1 |
|-----------|--------|
| Connect | 0x28 (Idempotent + NoFack) |
| Write | 0x20 (Idempotent only) |
| PrmEnd | 0x28 (Idempotent + NoFack) |

---

## 6. Step 4: Module Parameterization (Write)

### MultipleWrite (Index 0xE040)

Send a Write request (opnum 3) containing an outer IODWriteReqHeader with index 0xE040, wrapping multiple inner IODWriteReqHeaders for each parameter record.

### IODWriteReqHeader (64 bytes each)

```
BlockType    = 0x0008
BlockLength  = 60
Version      = 1.0
SeqNumber    = 0 (outer), 1-N (inner records)
ARUUID       = big-endian
API          = 0xFFFFFFFF (outer) or 0x00000000 (inner)
Slot         = 0xFFFF (outer) or actual slot (inner)
Subslot      = 0xFFFF (outer) or actual subslot (inner)
Index        = 0xE040 (outer) or record index (inner)
RecordDataLength = total inner size (outer) or data size (inner)
+ 24 bytes padding
```

### Parameter Records

| # | Slot | Subslot | Index | Size | Description |
|---|------|---------|-------|------|-------------|
| 1 | 0 | 1 | 0x0002 | 8 | DAP parameter |
| 2 | 1 | 1 | 0x00F3 | 4 | DQ isochronous mode |
| 3 | 1 | 1 | 0x0080 | 18 | DQ channel config |
| 4 | 2 | 1 | 0x00F3 | 4 | AI isochronous mode |
| 5 | 2 | 1 | 0x0080 | 178 | AI channel config (see Section 11) |

### Record data bytes

**Record 1** (DAP, Index 0x0002, 8 bytes):
```
08 01 00 00 00 00 00 00
```

**Record 2** (DQ, Index 0x00F3, 4 bytes):
```
01 00 00 00
```

**Record 3** (DQ, Index 0x0080, 18 bytes):
```
00 02 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00 01
```

**Record 4** (AI, Index 0x00F3, 4 bytes):
```
00 00 00 00
```

**Record 5** (AI, Index 0x0080, 178 bytes): See Section 11.

### Padding between records

Records must be padded to 4-byte boundaries **between** records, but **NOT after the last record**. Getting this wrong causes a payload size mismatch.

### Write Response Validation

The response contains:
- PNIOStatus (4 bytes) — must be `00 00 00 00`
- ArgsLength (4 bytes, LE) — should be > 0
- NDR header + individual IODWriteRes blocks per record

**If PNIOStatus is not all zeros, the parameterization failed.** Common error: `00 40 81 DF` = invalid record data in one of the parameter records.

---

## 7. Step 5: PrmEnd

Send a Control request (opnum 4) with IODControlReq block:

```
BlockType        = 0x0110 (PrmEnd)
BlockLength      = 28
Version          = 1.0
Reserved         = 0x0000
ARUUID           = big-endian
SessionKey       = 1
Reserved         = 0x0000
ControlCommand   = 0x0001 (PrmEnd)
ControlBlockProp = 0x0000
```

Wrap in NDR with `args_maximum=32`.

**Response**: Should contain IODControlRes (BlockType 0x8110) with ControlCommand=Done(0x0008).

**Validation**: Check response length >= 20 bytes. Do NOT parse specific byte offsets as PNIO error — the response contains the IODControlRes block header which can be misinterpreted as an error code.

---

## 8. Step 6: ApplicationReady

**This is the trickiest part of the protocol.**

### Race condition: socket MUST be open before PrmEnd

The device sends ApplicationReady within milliseconds of receiving PrmEnd. If you open the listening socket AFTER sending PrmEnd, you'll miss it.

**Correct sequence:**
1. Open UDP socket on port 34964 **BEFORE** sending PrmEnd
2. Send PrmEnd, receive PrmEnd response
3. Receive ApplicationReady on port 34964
4. Send proper response

### ApplicationReady request (from device)

The device sends a CControl request (opnum 4) to port 34964 with:
- Interface UUID = **Controller Interface** (`dea00002-...`), not Device Interface
- BlockType = 0x0112 (IOXBlockReq ApplicationReady)
- ControlCommand = 0x0002 (ApplicationReady)

Body structure (52 bytes):
```
ArgsMaximum  (4, LE) = e.g., 142
ArgsLength   (4, LE) = 32
MaxCount     (4, LE) = 142
Offset       (4, LE) = 0
ActualCount  (4, LE) = 32
IOXBlockReq  (32 bytes):
  BlockType       = 0x0112
  BlockLength     = 28
  Version         = 1.0
  Reserved        = 0x0000
  ARUUID          = big-endian
  SessionKey      = 1
  Reserved        = 0x0000
  ControlCommand  = 0x0002 (ApplicationReady)
  ControlBlockProp = 0x0000
```

### ApplicationReady response (from controller)

**You CANNOT just echo the request body.** Three fields must be changed:

| Field | Request value | Response value |
|-------|--------------|----------------|
| Bytes 0-3 (ArgsMaximum → PNIOStatus) | ArgsMaximum (e.g., 0x8E000000) | `00 00 00 00` (OK) |
| Bytes 20-21 (BlockType) | `01 12` (IOXBlockReq) | `81 12` (IOXBlockRes) |
| Bytes 48-49 (ControlCommand) | `00 02` (ApplicationReady) | `00 08` (Done) |

**RPC response header:**
```
packet_type = RESPONSE (2)
flags1 = 0x0A (NoFack + LastFragment)
interface_uuid = PNIO Controller Interface (dea00002-...)
activity_uuid = copied from request
sequence_number = copied from request
operation = copied from request (4)
```

**Failure mode**: If you echo the request body unchanged, the device sends an ERR-RTA-PDU alarm with error `CF 81 FD 18` = "SubmoduleState wrong" and aborts the AR. No cyclic data will be received.

---

## 9. Step 7: Cyclic RTC Data Exchange

### Output frame (controller → device)

Raw Ethernet frame, NO VLAN tag:

```
Dst MAC (6)     = device_mac
Src MAC (6)     = controller_mac
EtherType (2)   = 0x8892
FrameID (2)     = output_frame_id (from Connect Response, e.g., 0x8000)
RTC Data (40)   = output payload
CycleCounter (2) = incrementing counter
DataStatus (1)  = 0x35 (Primary + DataValid + Run + Normal)
TransferStatus (1) = 0x00
```

**Output payload (40 bytes):**
```
Offset  Content
0       DAP IOCS (0x80 = good)
1       Port 0 IOCS (0x80)
2       Port 1 IOCS (0x80)
3       Port 2 IOCS (0x80)
4       DQ data byte (bit 0=contactor, bits 1-4=SSRs)
5       DQ IOPS (0x80 = good)
6       AI IOCS (0x80)
7       Server IOCS (0x80)
8-39    Zero padding
```

### Input frame (device → controller)

Raw Ethernet frame WITH VLAN tag (802.1Q, priority 6):

```
Dst MAC (6)     = controller_mac
Src MAC (6)     = device_port_mac (may differ from DCP MAC!)
802.1Q tag (4)  = 81 00 A0 00
EtherType (2)   = 0x8892
FrameID (2)     = input_frame_id (e.g., 0xBB80)
RTC Data (40)   = input payload
CycleCounter (2)
DataStatus (1)
TransferStatus (1)
```

**Input payload (40 bytes):**
```
Offset  Content
0       DAP IOPS
1       Port 0 IOPS
2       Port 1 IOPS
3       Port 2 IOPS
4       DQ IOCS (consumer status)
5-20    AI data (8 channels x 2 bytes, big-endian signed int16, in 0.1 deg C)
21      AI IOPS
22      Server IOPS
23-39   Padding
```

### Temperature extraction

```python
for ch in range(4):
    offset = 5 + ch * 2  # INPUT_AI_DATA_OFFSET + channel * 2
    raw = struct.unpack("!h", data[offset:offset + 2])[0]  # signed int16 BE
    temp_celsius = raw / 10.0  # value in 0.1 deg C
```

### CRITICAL: Device port MAC

Siemens ET200SP sends RTC frames from its **port MAC** (device_mac + 1 for port 1), NOT the management MAC discovered via DCP. If you filter the sniffer by source MAC, you'll miss all device frames.

**Solution**: Use `ether proto 0x8892` as the BPF filter, NOT `ether src {device_mac}`.

### CRITICAL: Timing

The device's AR watchdog starts after ApplicationReady. Output frames must flow immediately — any delay (even 2 seconds for a diagnostic capture) causes the AR watchdog to timeout and the device aborts the connection.

**Start the RTC send loop immediately after ApplicationReady, with NO delays.**

### Sending with Scapy

```python
from scapy.all import Ether, sendp, AsyncSniffer

# Send output frame
sendp(Ether(raw_frame_bytes), iface=interface_name, verbose=False)

# Receive with async sniffer
sniffer = AsyncSniffer(
    iface=interface_name,
    filter="ether proto 0x8892",
    prn=callback_function,
    store=False,
)
sniffer.start()
```

---

## 10. Step 8: Disconnect / Release

Send a Control request (opnum 4) with:
```
BlockType        = 0x0114 (Release)
ControlCommand   = 0x0004 (Release)
```

Then close all sockets and stop the RTC exchange.

**Before releasing**: Set all outputs to 0 (safety).

---

## 11. AI Module Configuration (GSDML)

The AI 8xRTD/TC module parameter record (Index 0x0080, 178 bytes) is critical. Wrong values cause the module to read garbage data.

### Record structure

```
Header (2 bytes): 10 16
Channel 0 (22 bytes)
Channel 1 (22 bytes)
...
Channel 7 (22 bytes)
Total: 2 + 8 * 22 = 178 bytes
```

### Channel block layout (22 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-1 | Uint16 BE | Measurement type | Sensor type selection |
| 2 | Uint8 | Temperature coefficient | RTD only, irrelevant for TC |
| 3 low nibble | 4 bits | Smoothing | 0=none, 1=small, 2=mean, 3=strong |
| 3 high nibble | 4 bits | Integration time | 1=60Hz, 2=50Hz (default), 4=16.6Hz |
| 4 bits 0-1 | 2 bits | Temperature unit | 0=Celsius, 1=Fahrenheit, 2=Kelvin |
| 4 bits 4-7 | 4 bits | Reference junction | 0=none, 2=external RTD, 3=internal, 15=no compensation |
| 5 | bits | Process alarms | PRAL flags |
| 6 | bits | Diagnostics | Wire break, overflow, underflow flags |
| 7 | bits | Changeable range | Resolution config |
| 8-9 | | Reserved | |
| 10-11 | Int16 BE | Upper limit 1 | Default: 8500 (850.0 deg C) |
| 12-13 | Int16 BE | Lower limit 1 | Default: -2000 (-200.0 deg C) |
| 14-15 | Int16 BE | Upper limit 2 | Default: 8500 |
| 16-17 | Int16 BE | Lower limit 2 | Default: -2000 |
| 18-19 | Uint16 BE | Conductor resistance | Default: 0 |
| 20-21 | Int16 BE | Temperature offset | Default: 0 |

### Measurement type values (bytes 0-1)

**RTD types (0x09xx):**
| Value | Type |
|-------|------|
| 0x0902 | Pt100 Standard Range |
| 0x0903 | Pt100 Climate Range |
| 0x090C | Pt1000 Standard Range |

**Thermocouple types (0x0Axx):**
| Value | Type |
|-------|------|
| 0x0A00 | TC Type B |
| 0x0A01 | TC Type N |
| 0x0A05 | TC Type J |
| 0x0A07 | TC Type T |
| **0x0A08** | **TC Type K** |
| 0x0A0A | TC Type C |

### Reference junction values (byte 4, bits 4-7)

| Value | Meaning |
|-------|---------|
| 0 | No reference temperature source |
| 2 | External reference from RTD channel 0 |
| **3** | **Internal reference from base unit** |
| 15 | No compensation |

### Correct channel block for Type K TC with internal reference

```python
ai_channel = bytes([
    0x0A, 0x08,  # Measurement type = TC Type K
    0x00,        # Temp coefficient (N/A for TC)
    0x20,        # Smoothing=none, Integration=50Hz
    0x30,        # Celsius + internal reference junction (3 << 4 = 0x30)
    0x00,        # No process alarms
    0x00,        # No diagnostics enabled
    0x04,        # Changeable range config
    0x00, 0x00,  # Reserved
    0x21, 0x34,  # Upper limit 1 = 8500
    0xF8, 0x30,  # Lower limit 1 = -2000
    0x21, 0x34,  # Upper limit 2 = 8500
    0xF8, 0x30,  # Lower limit 2 = -2000
    0x00, 0x00,  # Conductor resistance = 0
    0x00, 0x00,  # Temperature offset = 0
])
```

### Common mistake

The Proneta capture we initially used had the module configured as **Pt100 RTD** (0x0902) instead of **TC Type K** (0x0A08). This caused the module to output nonsensical temperature readings (-215 deg C). The GSDML file is the source of truth for parameter encoding.

---

## 12. Complete Bug List & Solutions

### Bug 1: DCE/RPC header missing interface_version field
**Symptom**: Device silently drops all RPC packets.
**Cause**: Missing 4-byte `interface_version` field at offset 60, causing all subsequent fields to shift.
**Fix**: Include `interface_version` in header pack (1 for PNIO, 3 for EPM).

### Bug 2: Operation field packed as 4 bytes instead of 2
**Symptom**: Device silently drops all RPC packets.
**Cause**: `operation` packed as `<I` (4 bytes) instead of `<H` (2 bytes).
**Fix**: Use `struct.pack("<H", self.operation)`.

### Bug 3: UUID encoding wrong in PROFINET blocks
**Symptom**: PNIO error code=8, decode=1, code1=0x81, code2=0xDB.
**Cause**: Using DCE/RPC mixed-endian (`uuid_to_bytes_le`) inside PROFINET blocks.
**Fix**: Use `uuid_to_bytes_be()` for all UUIDs inside block payloads.

### Bug 4: RPC socket not bound to controller IP
**Symptom**: No responses received from device.
**Cause**: Socket bound to 0.0.0.0, OS picks wrong source IP (169.254.x.x).
**Fix**: Bind socket to the controller's IP on the device's subnet.

### Bug 5: ApplicationReady race condition
**Symptom**: ApplicationReady timeout (10 seconds, never received).
**Cause**: Listening socket opened AFTER PrmEnd sent; device responds within milliseconds.
**Fix**: Open UDP socket on port 34964 BEFORE sending PrmEnd.

### Bug 6: ApplicationReady response echoes request body
**Symptom**: Device sends ERR-RTA-PDU alarm (`CF 81 FD 18` = "SubmoduleState wrong"), no cyclic data.
**Cause**: Response body must differ from request in 3 fields (PNIOStatus, BlockType, ControlCommand).
**Fix**: Set bytes 0-3 to `00 00 00 00`, change block type 0x0112→0x8112, change ControlCommand 0x0002→0x0008.

### Bug 7: AI module parameter data wrong (Pt100 instead of TC Type K)
**Symptom**: Thermocouples read -215 deg C instead of ~30 deg C.
**Cause**: Channel measurement type set to 0x0902 (Pt100 RTD) instead of 0x0A08 (TC Type K). Reference junction set to 0 (none) instead of 3 (internal).
**Fix**: Change bytes 0-1 from `09 02` to `0A 08`, byte 4 from `00` to `30`.

### Bug 8: Write response not checking PNIO status
**Symptom**: Write "succeeds" (no exception) but device rejects parameters.
**Cause**: Only checking response length, not the PNIO status bytes.
**Fix**: Check first 4 bytes = `00 00 00 00`.

### Bug 9: MultipleWrite last record padding
**Symptom**: Write payload 2 bytes too long vs Proneta capture.
**Cause**: Padding ALL records to 4-byte boundary, including the last one.
**Fix**: Only pad between records, not after the last one.

### Bug 10: RTC sniffer using MAC filter misses device frames
**Symptom**: RTC frames sent but none received; sniffer sees nothing.
**Cause**: Device sends from port MAC (device_mac+1), not the DCP-discovered management MAC.
**Fix**: Use `ether proto 0x8892` BPF filter instead of MAC-based filter.

### Bug 11: 2-second diagnostic capture blocking RTC send thread
**Symptom**: Device aborts AR after first output frame, sends alarm.
**Cause**: Blocking `sniff(timeout=2)` call delayed output frames, triggering AR watchdog.
**Fix**: Remove any blocking operations between ApplicationReady and RTC start.

### Bug 12: PrmEnd response check reading block header as error
**Symptom**: PrmEnd falsely reported as failed.
**Cause**: Code checked `resp[20:24]` which reads IODControlRes block header `0x8110` as a PNIO error.
**Fix**: Use length-based check (`if len(resp) < 20`) instead of byte-value check.

### Bug 13: Panel manager sensor fault log spam
**Symptom**: Thousands of warning lines per second in console.
**Cause**: Logging "sensor fault" on every control loop iteration (10 Hz x 4 panels).
**Fix**: Only log on state transitions (when `was_fault != panel.fault`).

---

## 13. Wireshark Analysis Tips

### Useful display filters

```
pn_rt                           # All PROFINET RT frames
pn_io                           # PROFINET IO (RPC-based)
pn_io.ar_type                   # Connect requests
pn_io.control_command           # PrmEnd / ApplicationReady
dcerpc.opnum == 3               # Write requests
dcerpc.opnum == 0               # Connect requests
pn_rt.frame_id == 0xbb80        # Specific RTC frame ID
eth.type == 0x8892              # All PROFINET Ethernet frames
```

### Capturing the right traffic

1. **Proneta reference capture**: Run Proneta IO Test and capture the full session. This gives you a byte-perfect reference for Connect, Write, PrmEnd, AppReady, and RTC frames.

2. **Compare requests**: Export hex from both Proneta and your app, diff them byte-by-byte. Tools: Wireshark "Follow UDP Stream" or `tshark -T fields -e data.data`.

3. **Look for alarm frames**: FrameID 0xFE01 = alarm. The PNIOStatus in the alarm body tells you what went wrong.

### Key Proneta capture frames (for our ET200SP)

| Frame | Content |
|-------|---------|
| ~498 | Connect Request (ARBlock + IOCRBlocks + ExpectedSubmodule + AlarmCR) |
| ~500-501 | Write (MultipleWrite with 5 parameter records) |
| ~504 | PrmEnd Request |
| ~505 | PrmEnd Response |
| ~506 | ApplicationReady Request (from device) |
| ~507 | ApplicationReady Response (from controller) |
| ~508+ | RTC cyclic frames begin |

---

## 14. File Structure

```
panel-controller/
├── main.py                     # Entry point (PyQt6 app)
├── requirements.txt            # Dependencies
├── profinet/
│   ├── __init__.py
│   ├── dcp.py                  # DCP discovery & IP assignment (wraps pnio-dcp)
│   ├── protocol.py             # All PROFINET packet structures & constants
│   ├── rpc.py                  # DCE/RPC connection manager
│   ├── rtc.py                  # Cyclic RTC frame exchange (Scapy)
│   └── controller.py           # High-level orchestrator
├── control/
│   ├── __init__.py
│   ├── pid.py                  # PID controller with time-proportional output
│   └── panel_manager.py        # 4-panel heating control loop
├── gui/
│   ├── __init__.py
│   ├── main_window.py          # Main window
│   ├── panel_widget.py         # Per-panel temperature/control display
│   └── network_widget.py       # Network adapter selection, connect/disconnect
└── utils/
    ├── __init__.py
    └── network.py              # Network adapter enumeration
```

---

## Quick Reference: Module Identifiers

| Module | ModuleIdent | SubmoduleIdent | I/O |
|--------|-------------|----------------|-----|
| DAP (IM 155-6 PN BA) | 0x00064704 | 0x00000002 | None |
| Interface | — | 0x00008002 | None |
| Port 1 | — | 0x0000C000 | None |
| Port 2 | — | 0x0000C000 | None |
| DQ 8x24VDC/0.5A | 0x00004D9C | 0x00000008 | 1 byte out |
| AI 8xRTD/TC 2-wire HF | 0x00004A7F | 0x00000008 | 16 bytes in |
| Server | 0x00004710 | 0x00000000 | None |

**Note**: Module identifiers come from the GSDML file and vary between module hardware versions. Always verify against the actual GSDML for your hardware.
