import sys, struct; sys.path.insert(0,'/tmp')
from pe import PE
def funcs(pe):
    for n,va,vsz,raw,rsz,ch in pe.secs:
        if n=='.pdata':
            d=pe.d[raw:raw+vsz]
            out=[]
            for i in range(0,len(d)-11,12):
                b,e,u=struct.unpack_from('<III',d,i)
                if b==0 and e==0: break
                out.append((b,e))
            return out
    return []
def containing(fs,rva):
    for b,e in fs:
        if b<=rva<e: return (b,e)
    return None
if __name__=='__main__':
    pe=PE('windows_driver_binaries/GoodixMocWbdi.dll')
    fs=funcs(pe)
    print("Funktionen in .pdata:",len(fs))
    # gf_hmac_sha256-String-Ref war bei .text off 0x3ce84 -> RVA
    tva,_=pe.text()
    for label,textoff in [('gf_hmac_sha256-ref',0x3ce84),('gf_sha256-ref',0x3a7dd)]:
        rva=tva+textoff
        fn=containing(fs,rva)
        if fn:
            print("%s @ RVA 0x%x liegt in Funktion RVA 0x%x..0x%x (VA 0x%x, %d Bytes)"%(
                label,rva,fn[0],fn[1],pe.image_base+fn[0],fn[1]-fn[0]))
