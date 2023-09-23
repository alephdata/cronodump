from .kodump import kod_hexdump
from .koddecoder import match_with_mismatches
from .hexdump import unhex, tohex, asambigoushex, asasc, as1251
from .readers import ByteReader
from .Database import Database
from .Datamodel import TableDefinition


def destruct_sys3_def(rd):
    # todo
    pass


def destruct_sys4_def(rd):
    """
    decode type 4 of the records found in CroSys.

    This function is only useful for reverse-engineering the CroSys format.
    """
    n = rd.readdword()
    for _ in range(n):
        marker = rd.readdword()
        description = rd.readlongstring()
        path = rd.readlongstring()
        marker2 = rd.readdword()

        print("%08x;%08x: %-50s : %s" % (marker, marker2, path, description))


def destruct_sys_definition(args, data):
    """
    Decode the 'sys' / dbindex definition

    This function is only useful for reverse-engineering the CroSys format.
    """
    rd = ByteReader(data)

    systype = rd.readbyte()
    if systype == 3:
        return destruct_sys3_def(rd)
    elif systype == 4:
        return destruct_sys4_def(rd)
    else:
        raise Exception("unsupported sys record")


def cro_dump(kod, args):
    """handle 'crodump' subcommand"""
    if args.maxrecs:
        args.maxrecs = int(args.maxrecs, 0)
    else:
        # an arbitrarily large number.
        args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, args.compact, kod)
    db.dump(args)


def stru_dump(kod, args):
    """handle 'strudump' subcommand"""
    db = Database(args.dbdir, args.compact, kod)
    db.strudump(args)


def sys_dump(kod, args):
    """hexdump all CroSys records"""
    # an arbitrarily large number.
    args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, args.compact, kod)
    if db.sys:
        db.sys.dump(args)


def rec_dump(kod, args):
    """hexdump all records of the specified CroXXX.dat file."""
    if args.maxrecs:
        args.maxrecs = int(args.maxrecs, 0)
    else:
        # an arbitrarily large number.
        args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, args.compact, kod)
    db.recdump(args)


def destruct(kod, args):
    """
    decode the index#1 structure information record
    Takes hex input from stdin.
    """
    import sys

    data = sys.stdin.buffer.read()
    data = unhex(data)

    if args.type == 1:
        # create a dummy db object
        db = Database(".", args.compact)
        db.dump_db_definition(args, data)
    elif args.type == 2:
        tbdef = TableDefinition(data)
        tbdef.dump(args)
    elif args.type == 3:
        destruct_sys_definition(args, data)


def color_code(c, confidence, force):
    from sys import stdout
    is_a_tty = hasattr(stdout, 'isatty') and stdout.isatty()
    if not force and not is_a_tty:
        return c

    if confidence < 0:
        # cyan
        return "\033[96m" + c + "\033[0m"
    if confidence == 0:
        # red
        return "\033[31m" + c + "\033[0m"
    if confidence == 255:
        # green
        return "\033[32m" + c + "\033[0m"
    if confidence > 3:
        # yellow
        return "\033[93m" + c + "\033[0m"
    # blue
    return "\033[94m" + c + "\033[0m"


def strucrack(kod, args):
    """
    This function derives the KOD key from the assumption that most bytes in
    the CroStru records will be zero, given a sufficient number of CroStru
    items, statistically the most common bytes will encode to '0x00'
    """
    # start without 'KOD' table, so we will get the encrypted records
    db = Database(args.dbdir, args.compact, None)
    if args.sys:
        table = db.sys
        if not db.sys:
            print("no CroSys.dat file found in %s" % args.dbdir)
            return
    else:
        table = db.stru
        if not db.stru:
            print("no CroStru.dat file found in %s" % args.dbdir)
            return

    xref = [[0] * 256 for _ in range(256)]
    for i, data in enumerate(table.enumrecords()):
        if not data:
            continue
        for ofs, byte in enumerate(data):
            xref[(ofs + i + 1) % 256][byte] += 1

    KOD = [0] * 256
    KOD_CONFIDENCE = [0] * 256
    for i, xx in enumerate(xref):
        k, v = max(enumerate(xx), key=lambda kv: kv[1])
        KOD[k] = i
        KOD_CONFIDENCE[k] = v

    for fix in args.fix or []:
        # manage escaping on special characters
        fix = fix.replace('\\', "")
        # space is a special case
        fix = fix + ' ' if fix.endswith('=') else fix

        if len(fix) != 6:
            print("Invalid Fix format. Use xxyy=C or xxyycc")
            print(fix)
            continue

        if (fix[4] != "="):
            i, o, c = unhex(fix)
        else:
            i, o = unhex(fix[0:4])
            c, = as1251(fix[5:])

        KOD[i] = (c + o) % 256
        KOD_CONFIDENCE[i] = 255

    # For chunks of text where record and offset is known, set the KOD
    for fix in args.text or []:
        record, line, offset, text = fix.split(':', 4)
        data = table.readrec(int(record) + 1)
        dataoff = int(line) + int(offset)
        o = int(record) + 1 + int(line) + int(offset)
        for i, c in enumerate(text):
            d = data[dataoff + i]
            KOD[d] = (int.from_bytes(as1251(c), "little") + o + i) % 256
            KOD_CONFIDENCE[d] = 255

    kod_set = set([v for o, v in enumerate(KOD) if KOD_CONFIDENCE[o] > 0])
    unset_entries = [o for o, v in enumerate(KOD) if KOD_CONFIDENCE[o] == 0]
    unused_values = [v for v in sorted(set(range(0, 256)).difference(kod_set))]

    # if there's only one mapping missing in KOD and only one value not used, we
    # just assume those to belong together with a low confidence
    if len(unset_entries) == 1 and len(unused_values) == 1:
        entry = unset_entries[0]
        KOD[entry] = unused_values[0]
        KOD_CONFIDENCE[entry] = 1

    # Show duplicates that may arise by the user forcing KOD entries from command line
    kod_set = [v for o, v in enumerate(KOD) if KOD_CONFIDENCE[o] > 0]
    duplicates = [(o, v) for o, v in enumerate(KOD) if kod_set.count(v) > 1 and KOD_CONFIDENCE[o] > 0]
    duplicates = sorted(duplicates, key=lambda x: x[1])

    for o, v in duplicates:
        if KOD_CONFIDENCE[o] < 255:
            KOD_CONFIDENCE[o] = -1

    import crodump.koddecoder
    kod = crodump.koddecoder.new(KOD, KOD_CONFIDENCE)

    known_strings = [
        (b'USERINFO', 4, b'\x08USERINFO', -1),
        (b'Version', 4, b'\x07Version', -1),
        (b'\x08BankName', 5, b'\x08BankName', 0),
        (as1251("Системный номер"), 6, b'\x00\x00\x00\x00\x00\x00\x0f' + as1251("Системный номер") + b'\x01\x00\x00\x00\x00', -7)
    ]

    force_color = args.color

    # Dump partially decoded stru records for the user to try to spot patterns
    if not args.silent:
        w = args.width
        for i, data in enumerate(table.enumrecords()):
            if not data:
                continue

            print("Processing record number %d" % i)

            candidate, candidate_confidence = kod.try_decode(i + 1, data)

            for s, maxsubs, deststring, destoffset in known_strings:
                incomplete_matches = match_with_mismatches(candidate, candidate_confidence, s, maxsubs)
                # print(sisnm)
                for ofix in incomplete_matches:
                    do = ofix[0]
                    print("Found %s which looks a lot like %s " % (asasc(candidate[do:do + len(s)]), asasc(s)))
                    print("Add the following switches to your command line to fix the decoder box:\n    ", end='')
                    for o, c in enumerate(deststring):
                        print("-f %02x%02x%02x " % (data[do + o + destoffset], (do + i + 1 + o + destoffset) % 256, c), end='')
                    print("\n")

            candidate_chunks = [candidate[j:j + w] for j in range(0, len(candidate), w)]
            for ofs, chunk in enumerate(candidate_chunks):
                confidence = candidate_confidence[ofs * w:ofs * w + w]
                text = asasc(chunk, confidence)
                hexed = asambigoushex(chunk, confidence)

                colored = "".join(color_code(c, confidence[o], force_color) for o, c in enumerate(text))
                colored_hexed = "".join(color_code(c, confidence[o >> 1], force_color) for o, c in enumerate(hexed))
                fix_helper = " ".join("%02x%02x=%s" % (b, (w * ofs + i + 1 + o) % 256, color_code(text[o], confidence[o], force_color)) for o, b in enumerate(data[ofs * w:ofs * w + w]))

                # Can't use left padding in format string, because we have color escape codes,
                # so do manual padding
                padding = " " * (w - len(chunk))

                print("%05d %s : %s : %s" % (w * ofs, colored + padding, colored_hexed + padding * 2, fix_helper))
            print()

        if len(duplicates):
            print("\nDuplicates found:\n" + ", ".join(color_code("[%02x=>%02x (%d)]" % (o, v, KOD_CONFIDENCE[o]), KOD_CONFIDENCE[o], force_color) for o, v in duplicates))

        # If the KOD is not completely resolved, show the missing mappings
        unset_count = KOD_CONFIDENCE.count(0)
        if unset_count > 0:
            if args.noninteractive:
                return
            if not args.silent:
                unset_entries = ", ".join(["%02x" % o for o, v in enumerate(KOD) if KOD_CONFIDENCE[o] == 0])
                unused_values = ", ".join(["%02x" % v for v in sorted(set(range(0, 256)).difference(set(kod_set)))])
                print("\nAmbigous result when cracking. %d entries unsolved. Missing mappings:" % unset_count)
                print("[%s] => [%s]\n" % (unset_entries, unused_values))
                print("KOD estimate:")
                print("".join(color_code("%02x" % c if KOD_CONFIDENCE[o] > 0 else "??", KOD_CONFIDENCE[o], force_color) for o, c in enumerate(KOD)))

                print("\nIf you can provide clues for unresolved KOD entries by looking at the output, pass them via")
                print("crodump strucrack -f f103=B  -f f10342")
            return [0 if KOD_CONFIDENCE[o] == 0 else _ for o, _ in enumerate(KOD)]

    if not args.silent:
        print("Use the following database key to decrypt the database with crodump or croconvert with the --kod option:")
        print(tohex(bytes(KOD)))

    return KOD


def dbcrack(kod, args):
    """
    This function derives the KOD key from the assumption that most records in CroIndex
    and CroBank will be compressed, and start with:
      uint16 size
      byte  0x08
      byte  0x00

    So because the fourth byte in each record will be 0x00 when kod-decoded, I can
    use this as the inverse of the KOD table, adjusting for record-index.

    """
    # start without 'KOD' table, so we will get the encrypted records
    db = Database(args.dbdir, args.compact, None)
    xref = [[0] * 256 for _ in range(256)]

    for dbfile in db.bank, db.index:
        if not dbfile:
            print("no data file found in %s" % args.dbdir)
            return
        for i in range(1, min(10000, dbfile.nrofrecords)):
            rec = dbfile.readrec(i)
            if rec and len(rec) > 11:
                xref[(i + 3) % 256][rec[3]] += 1

    KOD = [0] * 256
    for i, xx in enumerate(xref):
        k, v = max(enumerate(xx), key=lambda kv: kv[1])
        KOD[k] = i

    if not args.silent:
        print(tohex(bytes(KOD)))

    return KOD


def main():
    import argparse

    class Cls:
        pass

    parser = argparse.ArgumentParser(description="CRO hexdumper")
    subparsers = parser.add_subparsers(title='commands', help='Use the --help option for the individual sub commands for more details')
    parser.set_defaults(handler=lambda *args: parser.print_help())
    parser.add_argument("--debug", action="store_true", help="break on exceptions")
    parser.add_argument("--kod", type=str, help="specify custom KOD table")
    parser.add_argument("--strucrack", action="store_true", help="infer the KOD sbox from CroStru.dat")
    parser.add_argument("--dbcrack", action="store_true", help="infer the KOD sbox from CroBank.dat + CroIndex.dat")
    parser.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")
    parser.add_argument("--compact", action="store_true", help="save memory by not caching the index, note: increases convert time by factor 1.15")

    p = subparsers.add_parser("kodump", help="KOD/hex dumper")
    p.add_argument("--offset", "-o", type=str, default="0")
    p.add_argument("--length", "-l", type=str)
    p.add_argument("--width", "-w", type=str)
    p.add_argument("--endofs", "-e", type=str)
    p.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")
    p.add_argument("--unhex", "-x", action="store_true", help="assume the input contains hex data")
    p.add_argument("--shift", "-s", type=str, help="KOD decode with the specified shift")
    p.add_argument("--increment", "-i", action="store_true",
                   help="assume data is already KOD decoded, but with wrong shift -> dump alternatives.")
    p.add_argument("--ascdump", "-a", action="store_true", help="CP1251 asc dump of the data")
    p.add_argument("--invkod", "-I", action="store_true", help="KOD encode")
    p.add_argument("filename", type=str, nargs="?", help="dump either stdin, or the specified file")
    p.set_defaults(handler=kod_hexdump)

    p = subparsers.add_parser("crodump", help="CROdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--maxrecs", "-m", type=str, help="max nr or recots to output")
    p.add_argument("--nodecompress", action="store_false", dest="decompress", default="true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=cro_dump)

    p = subparsers.add_parser("sysdump", help="SYSdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--nodecompress", action="store_false", dest="decompress", default="true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=sys_dump)

    p = subparsers.add_parser("recdump", help="record dumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--maxrecs", "-m", type=str, help="max nr or recots to output")
    p.add_argument("--find1d", action="store_true", help="Find records with 0x1d in it")
    p.add_argument("--stats", action="store_true", help="calc table stats from the first byte of each record",)
    p.add_argument("--index", action="store_true", help="dump CroIndex")
    p.add_argument("--stru", action="store_true", help="dump CroStru")
    p.add_argument("--bank", action="store_true", help="dump CroBank")
    p.add_argument("--sys", action="store_true", help="dump CroSys")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=rec_dump)

    p = subparsers.add_parser("strudump", help="STRUdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=stru_dump)

    p = subparsers.add_parser("destruct", help="Stru dumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--type", "-t", type=int, help="what type of record to destruct")
    p.set_defaults(handler=destruct)

    p = subparsers.add_parser("strucrack", help="Crack v4 KOD encrypion, bypassing the need for the database password.")
    p.add_argument("--sys", action="store_true", help="Use CroSys for cracking")
    p.add_argument("--silent", action="store_true", help="no output")
    p.add_argument("--noninteractive", action="store_true", help="Stop if automatic cracking fails")
    p.add_argument("--color", action="store_true", help="force color output even on non-ttys")
    p.add_argument("--fix", "-f", action="append", dest="fix", help="force KOD entries after identification")
    p.add_argument("--text", "-t", action="append", dest="text", help="add fixed bytes to decoder box by providing whole strings for a position in a record, format is record:line:offset:plaintext")
    p.add_argument("--width", "-w", type=int, help="max number of decoded characters on screen", default=24)

    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=strucrack)

    p = subparsers.add_parser("dbcrack", help="Crack v4 KOD encrypion, bypassing the need for the database password.")
    p.add_argument("--silent", action="store_true", help="no output")
    p.add_argument("dbdir", type=str)
    p.add_argument("--fix", "-f", action="append", dest="fix", help="force KOD entries after identification")
    p.add_argument("--text", "-t", action="append", dest="text", help="add fixed bytes to decoder box by providing whole strings for a position in a record, format is record:line:offset:plaintext")
    p.add_argument("--color", action="store_true", help="force color output even on non-ttys")
    p.add_argument("--width", "-w", type=int, help="max number of decoded characters on screen", default=24)
    p.set_defaults(handler=dbcrack)

    args = parser.parse_args()

    import crodump.koddecoder
    if args.kod:
        if len(args.kod) != 512:
            raise Exception("--kod should have a 512 hex digit argument")
        kod = crodump.koddecoder.new(list(unhex(args.kod)))
    elif args.nokod:
        kod = None
    elif args.strucrack:
        cargs = Cls()
        cargs.dbdir = args.dbdir
        cargs.sys = False
        cargs.silent = True
        cargs.noninteractive = False
        # collect all keys
        for k, v in args.__dict__.items():
            if not cargs.__dict__.get(k):
                cargs.__dict__.update({k: v})
        cracked = strucrack(None, cargs, printout=True)
        if not cracked:
            return
        kod = crodump.koddecoder.new(cracked)
    elif args.dbcrack:
        cargs = Cls()
        cargs.dbdir = args.dbdir
        cargs.sys = False
        cargs.silent = True
        cargs.noninteractive = False
        # collect all keys
        for k, v in args.__dict__.items():
            if not cargs.__dict__.get(k):
                cargs.__dict__.update({k: v})
        cracked = dbcrack(None, cargs)
        if not cracked:
            return
        kod = crodump.koddecoder.new(cracked)
    else:
        kod = crodump.koddecoder.new()

    if args.handler:
        # basically, struckrack() will be called twice
        args.handler(kod, args)


if __name__ == "__main__":
    main()
