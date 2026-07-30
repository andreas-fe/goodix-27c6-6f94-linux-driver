import sys, struct; sys.path.insert(0,'/tmp')
from pe import PE

def lea_rip_xrefs(pe, target_rva):
    """Findet LEA r64,[rip+disp32] (48/4C 8D /r mod=00 rm=101) die auf target_rva zeigen."""
    tva, text = pe.text()
    hits=[]
    n=len(text)
    for i in range(n-7):
        b0=text[i]
        if b0 not in (0x48,0x4c): continue
        if text[i+1]!=0x8d: continue
        modrm=text[i+2]
        if (modrm & 0xc7)!=0x05: continue   # mod=00, rm=101 => RIP-relative
        disp=struct.unpack_from('<i',text,i+3)[0]
        insn_end_rva = tva + i + 7
        tgt = insn_end_rva + disp
        if tgt==target_rva:
            reg = ((b0&1)<<3) | ((modrm>>3)&7)
            hits.append((tva+i, reg, 7))
    return hits

def any_rip_ref(pe, target_rva):
    """Alle RIP-relativen Referenzen (mov/lea/cmp ...) grob: scanne nach disp32, das auf target zeigt.
       Konservativ: teste jede 4-Byte-Stelle als potenzielles disp32 mit Instruktionsende 4..8 dahinter."""
    tva,text=pe.text(); hits=[]
    for i in range(len(text)-4):
        disp=struct.unpack_from('<i',text,i)[0]
        for end_gap in (4,):  # disp gefolgt vom Instruktionsende
            end_rva=tva+i+4
            if end_rva+disp==target_rva:
                hits.append(tva+i)
    return hits

if __name__=='__main__':
    pe=PE('windows_driver_binaries/GoodixMocWbdi.dll')
    for off,label in [(777832,'gf_sha256'),(777912,'gf_hmac_sha256'),
                      (3862222,'psk_derive_premaster'),(3857546,'derive_keys'),
                      (3863762,'TLS-PSK-suite')]:
        rva=pe.off2rva(off)
        lea=lea_rip_xrefs(pe,rva)
        print("\n=== '%s' (RVA 0x%x): %d LEA-Xref(s) ==="%(label,rva,len(lea)))
        for addr,reg,_ in lea[:12]:
            regname=['ax','cx','dx','bx','sp','bp','si','di','r8','r9','r10','r11','r12','r13','r14','r15'][reg]
            print("   LEA r%s, [rip->str]  @ VA 0x%x  (.text off 0x%x)"%(regname,pe.image_base+addr,addr-pe.text()[0]))
