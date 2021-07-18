import struct
from binascii import b2a_hex, a2b_hex

"""
Simple hexdump, 16 bytes per line with offset.
"""


def unhex(data):
    if type(data) == bytes:
        data = data.decode("ascii")
    data = data.replace(" ", "")
    data = data.strip()
    return a2b_hex(data)


def ashex(line):
    return " ".join("%02x" % _ for _ in line)


def aschr(b):
    if 32 <= b < 0x7F:
        return "%c" % b
    elif 0x80 <= b <= 0xFF:
        try:
            c = struct.pack("<B", b).decode("cp1251")
            if c:
                return c
        except:
            pass
    return "."


def asasc(line):
    return "".join(aschr(_) for _ in line)


def hexdump(ofs, data, args):
    w = args.width
    if args.ascdump:
        fmt = "%08x: %s"
    else:
        fmt = "%%08x: %%-%ds  %%s" % (3 * w - 1)
    for o in range(0, len(data), w):
        if args.ascdump:
            print(fmt % (o + ofs, asasc(data[o : o + w])))
        else:
            print(fmt % (o + ofs, ashex(data[o : o + w]), asasc(data[o : o + w])))


def tohex(data):
    return b2a_hex(data).decode("ascii")


def toout(args, data):
    """return either ascdump or hexdump"""
    if args.ascdump:
        return asasc(data)
    else:
        return tohex(data)


def strescape(txt):
    if type(txt) == bytes:
        txt = txt.decode("cp1251")
    txt = txt.replace("\\", "\\\\")
    txt = txt.replace("\n", "\\n")
    txt = txt.replace("\r", "\\r")
    txt = txt.replace("\t", "\\t")
    txt = txt.replace('"', '\\"')
    return txt
