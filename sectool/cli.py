from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .core.context import Context
from .core.errors import ModuleUnavailableError, SectoolError
from .core.findings import Finding, Severity
from .core.logging import setup_logging
from .core.output import Reporter
from .modules import crypto, deps, packets, passwords, scan, ssl_audit

MODULES = [scan, ssl_audit, deps, packets, passwords, crypto]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity (-v, -vv)")
    common.add_argument("--json", action="store_true", help="Emit findings as JSON")
    common.add_argument("--no-color", action="store_true", help="Disable colored output")
    common.add_argument("--min-severity", default="info", metavar="LEVEL", help="Minimum severity to display")
    common.add_argument("--fail-on", default="low", metavar="LEVEL", help="Exit non-zero on findings at or above this severity")
    common.add_argument("--output", metavar="FILE", help="Write output to a file instead of stdout")

    parser = argparse.ArgumentParser(
        prog="sectool",
        description="sectool: a cybersecurity multi-tool CLI for security teams.",
    )
    parser.add_argument("--version", action="version", version=f"sectool {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    for module in MODULES:
        subparser = subparsers.add_parser(
            module.NAME,
            help=module.HELP,
            description=module.HELP,
            parents=[common],
        )
        module.configure_parser(subparser)
        subparser.set_defaults(handler=module.run)

    return parser


def _use_color(args, stream) -> bool:
    if args.no_color or args.json:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _exit_code(findings: Optional[List[Finding]], fail_on: Severity) -> int:
    if not findings:
        return EXIT_OK
    if any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        min_severity = Severity.from_name(args.min_severity)
        fail_on = Severity.from_name(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))

    logger = setup_logging(args.verbose, json_format=args.json)

    stream = sys.stdout
    file_handle = None
    if args.output:
        try:
            file_handle = open(args.output, "w", encoding="utf-8")
            stream = file_handle
        except OSError as exc:
            logger.error("cannot open output file '%s': %s", args.output, exc)
            return EXIT_ERROR

    reporter = Reporter(
        fmt="json" if args.json else "text",
        color=_use_color(args, stream),
        min_severity=min_severity,
        stream=stream,
    )
    context = Context(reporter=reporter, logger=logger)

    try:
        result = args.handler(args, context)
    except ModuleUnavailableError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except SectoolError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        logger.error("interrupted")
        return EXIT_INTERRUPTED
    except Exception as exc:
        logger.exception("unexpected error: %s", exc)
        return EXIT_ERROR
    finally:
        if file_handle is not None:
            file_handle.close()

    if isinstance(result, int):
        return result
    return _exit_code(result, fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
