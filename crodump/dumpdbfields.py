import os
import os.path
from Database import Database
from hexdump import asasc


class Cls:
    pass


def main():
    import sys

    dbpath = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.getenv("HOME"), "prj/cronos")
    )
    args = Cls()
    args.verbose = False

    for path, _, files in os.walk(dbpath):
        if any(_ for _ in files if _.lower() == "crostru.dat"):
            print(path)

            db = Database(path)
            for tab in db.enumerate_tables():
                tab.dump(args)
                print("nr=%d" % db.nrofrecords())
                i = 0
                for rec in db.enumerate_records(tab):
                    for field, fielddef in zip(rec.fields, tab.fields):
                        print(">> %s -- %s" % (fielddef, field.content))
                    i += 1
                    if i > 100:
                        break


if __name__ == "__main__":
    main()
