from readers import ByteReader
from TableDefinition import TableDefinition
from hexdump import ashex


class Field:
    def __init__(self, fielddef, data):
        self.decode(fielddef, data)

    def decode(self, fielddef, data):
        self.typ = fielddef.typ

        # decode internal file reference
        if self.typ == 6:
            rd = ByteReader(data)
            self.flag = rd.readdword()
            self.remlen = rd.readdword()
            self.filename = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.extname = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.filedatarecord = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.content = " ".join([self.filename, self.extname, self.filedatarecord])
        else:
            self.content = data.decode("cp1251")


class Record:
    def __init__(self, tabledef, data):
        self.decode(tabledef, data)

    def decode(self, tabledef, data):
        """
        decode the fields in a record
        """
        self.data = data
        self.table = tabledef

        self.fields = []
        rd = ByteReader(data)
        for fielddef in tabledef[1:]:
            # read complex record indicated by b"\x1b"
            if rd.testbyte(27):
                rd.readbyte()
                size = rd.readdword()
                fielddata = rd.readbytes(size)
            else:
                fielddata = rd.readtoseperator(b"\x1e")

            self.fields.append(Field(fielddef, fielddata))
