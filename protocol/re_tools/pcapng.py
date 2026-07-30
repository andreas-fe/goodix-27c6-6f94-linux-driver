import struct, sys

def blocks(d):
    off = 0
    while off + 12 <= len(d):
        btype, blen = struct.unpack_from('<II', d, off)
        if blen < 12 or off + blen > len(d): break
        yield btype, d[off+8:off+blen-4]
        off += blen

def usb_packets(path):
    d = open(path,'rb').read()
    out = []
    for btype, body in blocks(d):
        if btype != 6:  # Enhanced Packet Block
            continue
        iface, tsh, tsl, cap, orig = struct.unpack_from('<IIIII', body, 0)
        pkt = body[20:20+cap]
        # Linux usbmon header ist 64 Byte
        if len(pkt) < 64: continue
        urb_type = pkt[8]           # 'S'=submit 'C'=complete
        xfer     = pkt[9]
        epnum    = pkt[10]
        data_len = struct.unpack_from('<I', pkt, 36)[0]
        payload  = pkt[64:64+data_len]
        out.append((chr(urb_type), epnum, payload))
    return out
