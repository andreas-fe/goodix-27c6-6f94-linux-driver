import struct
class PE:
    def __init__(self,path):
        self.d=open(path,'rb').read()
        d=self.d
        e=struct.unpack_from('<I',d,0x3c)[0]
        assert d[e:e+4]==b'PE\0\0'
        coff=e+4
        self.nsec,=struct.unpack_from('<H',d,coff+2)
        optsz,=struct.unpack_from('<H',d,coff+16)
        opt=coff+20
        magic,=struct.unpack_from('<H',d,opt)
        self.pe32p=(magic==0x20b)
        self.image_base,=struct.unpack_from('<Q' if self.pe32p else '<I', d, opt+24)
        self.secs=[]
        st=opt+optsz
        for i in range(self.nsec):
            b=st+i*40
            name=d[b:b+8].rstrip(b'\0').decode('latin1',errors='replace')
            vsz,va,rsz,raw=struct.unpack_from('<IIII',d,b+8)
            ch,=struct.unpack_from('<I',d,b+36)
            self.secs.append((name,va,vsz,raw,rsz,ch))
    def off2rva(self,off):
        for n,va,vsz,raw,rsz,ch in self.secs:
            if raw<=off<raw+rsz: return va+(off-raw)
        return None
    def rva2off(self,rva):
        for n,va,vsz,raw,rsz,ch in self.secs:
            if va<=rva<va+max(vsz,rsz): return raw+(rva-va)
        return None
    def text(self):
        for n,va,vsz,raw,rsz,ch in self.secs:
            if n=='.text': return va,self.d[raw:raw+rsz]
        return None,b''
