import struct


class ByteReader:
    def __init__(self, data):
        self.data = data
        self.o = 0

    def readbyte(self):
        if self.o + 1 > len(self.data):
            raise Exception("EOF")
        self.o += 1
        return struct.unpack_from("<B", self.data, self.o - 1)[0]

    def readword(self):
        if self.o + 2 > len(self.data):
            raise Exception("EOF")
        self.o += 2
        return struct.unpack_from("<H", self.data, self.o - 2)[0]

    def readdword(self):
        if self.o + 4 > len(self.data):
            raise Exception("EOF")
        self.o += 4
        return struct.unpack_from("<L", self.data, self.o - 4)[0]

    def readbytes(self, n=None):
        if n is None:
            n = len(self.data) - self.o
        if self.o + n > len(self.data):
            raise Exception("EOF")
        self.o += n
        return self.data[self.o - n : self.o]

    def readlongstring(self):
        namelen = self.readdword()
        return self.readbytes(namelen).decode("cp1251")

    def readname(self):
        namelen = self.readbyte()
        return self.readbytes(namelen).decode("cp1251")

    def eof(self):
        return self.o >= len(self.data)
