from koddecoder import decode_kod
from Database import Database
from sys import exit, stdout
from os.path import dirname, abspath, join
import base64

"""
python3 croconvert.py -t html chechnya_proverki_ul_2012/
"""


def convert(args):
    """looks up template to convert to, parses the database and passes it to jinja2"""

    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        exit(
            "Fatal: Jinja templating engine not found. Install using pip install jinja2"
        )

    db = Database(args.dbdir)

    template_dir = join(dirname(dirname(abspath(__file__))), "templates")
    j2_env = Environment(loader=FileSystemLoader(template_dir))
    j2_templ = j2_env.get_template(args.template + ".j2")
    j2_templ.stream(db=db, base64=base64).dump(stdout)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CRONOS database coverter")
    parser.add_argument(
        "--template",
        "-t",
        help="output template to use for conversion",
        type=str,
        default="html",
    )
    parser.add_argument("dbdir", type=str)
    args = parser.parse_args()

    convert(args)


if __name__ == "__main__":
    main()
