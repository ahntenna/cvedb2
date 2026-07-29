import argparse
from datetime import datetime
from dateutil.parser import isoparse, ParserError
from pathlib import Path
import pkg_resources
import sys
from typing import List, Optional, Union

from .cpe import Logical
from .db import CVEdb, CVEdbPostExec, DEFAULT_DB_PATH
from .feed import Data, FEEDS
from .printing import print_cves
from .search import (
    AfterModifiedDateQuery, AfterPublishedDateQuery, AndQuery, BeforeModifiedDateQuery, BeforePublishedDateQuery,
    CPEQuery, Sort
)
from .report import take_snapshot, collect_details, write_csv, write_excel


def version() -> str:
    return pkg_resources.require("cvedb2")[0].version


def parse_date(date_str: str) -> datetime:
    try:
        return isoparse(date_str).astimezone()
    except ParserError:
        pass
    raise argparse.ArgumentTypeError(f"Invalid date {date_str!r}. Dates must be either a four digit year or an ISO "
                                     "8601 string. See https://dateutil.readthedocs.io/en/stable/parser.html "
                                     "for examples.")


def parse_cpe_arg(cpe_str: str) -> Union[Logical, str]:
    for logical in Logical:
        if logical.value == cpe_str:
            return logical
    return cpe_str


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--update", "-u", action="store_true", help="update the database to the latest version; this "
                                                                    "requires an Internet connection")
    parser.add_argument("--update-report", "-ur", action="store_true",
                        help="update the database and report newly added / modified CVEs to the console and to "
                             "CSV/Excel files")
    parser.add_argument("--output-dir", "-o", type=str, default=".",
                        help="directory to save the update report files (used with --update-report; default is the "
                             "current directory)")
    parser.add_argument("--format", "-f", choices=("csv", "excel", "all"), default="all",
                        help="update report file format (used with --update-report; default is all)")
    parser.add_argument("--since-year", "-y", type=int, default=None,
                        help="when updating, only check feeds for the given year and later (e.g., -y 2020; "
                             "note that the 2002 feed contains all CVEs from 1999-2002)")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=DEFAULT_DB_PATH,
                        help=f"alternative path to load/store the database (default is {DEFAULT_DB_PATH!s})")
    parser.add_argument("--sort", "-s", nargs="*", default=("cve",),
                        choices=("cve", "modified", "published", "impact", "severity"),
                        help="how to sort the results (default is by CVE ID only)")
    parser.add_argument("--descending", "-d", action="store_true",
                        help="reverse the ordering of results (default is ascending)")
    parser.add_argument("--after", "-a", type=parse_date, help="only list CVEs published after the given date")
    parser.add_argument("--before", "-b", type=parse_date, help="only list CVEs published before the given date")
    parser.add_argument("--modified-after", "-ma", type=parse_date, help="only list CVEs modified after the given date")
    parser.add_argument("--modified-before", "-mb", type=parse_date,
                        help="only list CVEs modified before the given date")

    cpe_group = parser.add_argument_group(title="Common Platform Enumeration (CPE)",
                                          description="search options filtering by CPE")
    cpe_group.add_argument("--vendor", type=parse_cpe_arg, nargs="?", default=Logical.ANY,
                           help="search by software/hardware vendor")
    cpe_group.add_argument("--software-version", type=parse_cpe_arg, nargs="?", default=Logical.ANY,
                           help="search by version")

    parser.add_argument("--ansi", action="store_true", help="force ANSI colored output even when not printing to a TTY "
                                                            "(e.g., when piping output to a file or pager)")

    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")
    parser.add_argument("--data-version", "-dv", action="store_true", help="print the version of each of the CVE data "
                                                                           "feeds and exit")

    parser.add_argument("--data-index", "-di", action="store_true", help=f"create index for data (default is {DEFAULT_DB_PATH!s})")
    parser.add_argument("--vacuum", "-va", action="store_true", help="do vacuum")

    args = parser.parse_args(argv[1:])

    before_update = None
    after_update = None
    if args.update_report:
        before_update = take_snapshot(Path(args.database))
        print(f"before update count: {len(before_update):,}")

    if args.update:
        parents = None
        if args.since_year is not None:
            parents = [feed for name, feed in FEEDS.items() if name.isdigit() and int(name) >= args.since_year]
            if not parents:
                sys.stderr.write(f"No feeds found for year >= {args.since_year}\n")
                return 1
        with CVEdb.open(args.database, parents) as db:
            db.data().reload(force=True)

    if args.update_report and before_update is not None:
        after_update = take_snapshot(Path(args.database))
        print(f"after update count: {len(after_update):,}")

        if after_update is not None:
            new_keys = set(after_update) - set(before_update)
            modified_keys = {key for key in set(after_update) & set(before_update) if after_update[key] != before_update[key]}

            new_rows = collect_details(Path(args.database), new_keys)
            modified_rows = collect_details(Path(args.database), modified_keys)

            if new_rows or modified_rows:
                Path(args.output_dir).mkdir(parents=True, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                if args.format in ("csv", "all"):
                    csv_path = Path(args.output_dir) / f"cvedb2_update_report_{stamp}.csv"
                    write_csv(csv_path, new_rows, modified_rows)
                    print(f"save csv: {csv_path.resolve()}")
                if args.format in ("excel", "all"):
                    xlsx_path = Path(args.output_dir) / f"cvedb2_update_report_{stamp}.xlsx"
                    write_excel(xlsx_path, new_rows, modified_rows, Path(args.database), len(before_update), len(after_update))
                    print(f"save excel: {xlsx_path.resolve()}")

    if args.version:
        if sys.stdout.isatty():
            print(f"cvedb2 version {version()}")
        else:
            print(version())
        return 0
    elif args.data_version:
        with CVEdb.open(args.database) as db:
            rows = [["Feed", "Last Modified", "Last Checked", "# CVEs"]]
            for feed in db.feeds:
                lm: Union[Optional[datetime], str] = feed.last_modified()
                if lm is None:
                    lm = "never"
                else:
                    lm = lm.strftime("%Y-%m-%d")
                lc: Union[Optional[datetime], str] = feed.last_checked()
                if lc is None:
                    lc = "never"
                else:
                    lc = lc.strftime("%Y-%m-%d")
                rows.append([feed.name, lm, lc, str(len(feed.data()))])
            num_cols = len(rows[0])
            col_widths = [max(len(row[i]) for row in rows) for i in range(num_cols)]
            total_width = sum(col_widths) + num_cols + 1
            sys.stdout.write(f"+{'=' * (total_width - 2)}+\n")
            header = f"Database: {args.database!s}"
            if len(header) + 2 > total_width:
                header = f"Database: {str(args.database)[:total_width - 15]}..."
            else:
                header = f"{' ' * ((total_width - len(header)) // 2)}{header}"
                header = f"{header}{' ' * (total_width - len(header))}"
            sys.stdout.write(f"|{header}|\n")
            sys.stdout.write(f"+{'=' * (total_width - 2)}+\n")
            for i, header in enumerate(rows[0]):
                sys.stdout.write(f"|{header}{' ' * (col_widths[i] - len(header))}")
            sys.stdout.write("|\n")
            sys.stdout.write(f"+{'=' * (total_width - 2)}+\n")
            for row in rows[1:]:
                for i, col in enumerate(row):
                    sys.stdout.write(f"|{col}{' ' * (col_widths[i] - len(col))}")
                sys.stdout.write("|\n")
            sys.stdout.write(f"+{'=' * (total_width - 2)}+\n")
            return 0

    query = []
    if args.after:
        query.append(AfterPublishedDateQuery(args.after))
    if args.before:
        query.append(BeforePublishedDateQuery(args.before))
    if args.modified_before:
        query.append(BeforeModifiedDateQuery(args.modified_before))
    if args.modified_after:
        query.append(AfterModifiedDateQuery(args.modified_after))
    if args.SEARCH_TERM:
        query.append(Data.make_query(*args.SEARCH_TERM))

    if args.software_version != Logical.ANY or args.vendor != Logical.ANY:
        cpe = CPEQuery(
            vendor=args.vendor,
            version=args.software_version
        )
        query.append(cpe)
    if len(query) == 1:
        query = query[0]
    elif query:
        query = AndQuery(*query)
    else:
        query = None

    if args.data_index:
        with CVEdbPostExec(args.database) as post:
            post.create_index()
            print('create index success.')
        if not args.vacuum:
            return 0

    if args.vacuum:
        with CVEdbPostExec(args.database) as post:
            post.vacuum()
            print('vacuum success.')
        return 0

    try:
        with CVEdb.open(args.database) as db:
            if query is None:
                # just print all of the CVEs
                print_cves(db.data())
            else:
                sorts = []
                for sort in args.sort:
                    if sort == "cve":
                        sorts.append(Sort.CVE_ID)
                    elif sort == "modified":
                        sorts.append(Sort.LAST_MODIFIED_DATE)
                    elif sort == "published":
                        sorts.append(Sort.PUBLISHED_DATE)
                    elif sort == "impact":
                        sorts.append(Sort.IMPACT)
                    elif sort == "severity":
                        sorts.append(Sort.SEVERITY)
                if args.ansi:
                    force_ansi = True
                else:
                    force_ansi = None
                print_cves(
                    db.data().search(query, sort=sorts, ascending=not args.descending),
                    force_color=force_ansi
                )
        return 0
    except (KeyboardInterrupt, BrokenPipeError):
        return 1
