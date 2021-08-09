"""
Several functions for converting bytes to readable text or hex bytes.
"""
import struct
from binascii import b2a_hex, a2b_hex


def unhex(data):
    """
    convert a possibly space separated list of 2-digit hex values to a byte-array
    """
    if type(data) == bytes:
        data = data.decode("ascii")
    data = data.replace(" ", "")
    data = data.strip()
    return a2b_hex(data)


def ashex(line):
    """
    convert a byte-array to a space separated list of 2-digit hex values.
    """
    return " ".join("%02x" % _ for _ in line)


def aschr(b):
    """
    convert a CP-1251 byte to a unicode character.
    This will make both cyrillic and latin text readable.
    """
    if 32 <= b < 0x7F:
        return "%c" % b
    elif 0x80 <= b <= 0xFF:
        try:
            c = struct.pack("<B", b).decode("cp1251")
            if c:
                return c
        except UnicodeDecodeError:
            # 0x98 is the only invalid cp1251 character.
            pass
    return "."


def asasc(line):
    """
    convert a CP-1251 encoded byte-array to a line of unicode characters.
    """
    return "".join(aschr(_) for _ in line)


def hexdump(ofs, data, args):
    """
    Output offset prefixed lines of hex + ascii characters.
    """
    w = args.width
    if args.ascdump:
        fmt = "%08x: %s"
    else:
        fmt = "%%08x: %%-%ds  %%s" % (3 * w - 1)
    for o in range(0, len(data), w):
        if args.ascdump:
            print(fmt % (o + ofs, asasc(data[o:o+w])))
        else:
            print(fmt % (o + ofs, ashex(data[o:o+w]), asasc(data[o:o+w])))


def tohex(data):
    """
    Convert a byte-array to a sequence of 2-digit hex values without separators.
    """
    return b2a_hex(data).decode("ascii")


def toout(args, data):
    """
    Return either ascdump or hexdump, depending on the `args.ascdump` flag.
    """
    if args.ascdump:
        return asasc(data)
    else:
        return tohex(data)


def strescape(txt):
    """
    Convert bytes or text to a c-style escaped string.
    """
    if type(txt) == bytes:
        txt = txt.decode("cp1251")
    txt = txt.replace("\\", "\\\\")
    txt = txt.replace("\n", "\\n")
    txt = txt.replace("\r", "\\r")
    txt = txt.replace("\t", "\\t")
    txt = txt.replace('"', '\\"')
    return txt
