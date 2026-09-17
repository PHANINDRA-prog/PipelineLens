"""CLI for an opt-in, local public GitHub Actions failure corpus.

Examples:

``python -m pipelinelens.public_harvest --github-repo owner/name``
    validates and prints a local-only preview.

``python -m pipelinelens.public_harvest --github-repo owner/name --execute``
    performs bounded unauthenticated reads from ``https://api.github.com`` and writes
    sanitized observations under ignored ``data/public-corpus``.

``python -m pipelinelens.public_harvest --reevaluate --execute``
    reclassifies retained sanitized observations without network access.

No token argument exists. Output is summary metadata only: it never prints logs,
workflow source, source URLs, response headers, query strings, or error bodies.
Selected/new/already-retained counts describe this invocation; summary/retained counts
describe lifetime storage. Captured coverage is not training data or measured accuracy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from pipelinelens.services.public_corpus import (
    DEFAULT_RUNS_PER_REPOSITORY,
    PUBLIC_CORPUS_NOTICE,
    PublicCorpus,
    PublicCorpusError,
    harvest_public_repositories,
    preview_public_harvest,
    reevaluate_public_corpus,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Do not echo untrusted argv; a malformed URL could contain credentials or a query.
        del message
        self.exit(
            2,
            "Invalid arguments. Use --help; public corpus collection has no token "
            "option.\n",
        )


def _json_safe(value: object) -> object:
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _print(value: object) -> None:
    print(json.dumps(_json_safe(value), indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    """Run a local preview by default; only ``--execute`` enables collection or writes."""

    parser = _Parser(
        description="Local deterministic analysis of public GitHub Actions failures.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--github-repo",
        action="append",
        default=[],
        metavar="OWNER/NAME",
        help="Explicit public GitHub repository; repeat for multiple repositories.",
    )
    parser.add_argument(
        "--per-repo",
        type=int,
        default=DEFAULT_RUNS_PER_REPOSITORY,
        metavar="1-10",
        help="Latest failed workflow runs per repository (default: 4).",
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="Local corpus directory; default is ignored data/public-corpus.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Explicitly allow public API reads and local corpus writes.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--summary", action="store_true", help="Read local aggregate coverage only.")
    mode.add_argument(
        "--reevaluate",
        action="store_true",
        help="Reclassify retained sanitized observations locally.",
    )
    args = parser.parse_args(argv)
    if (args.summary or args.reevaluate) and args.github_repo:
        parser.error("Modes cannot be combined with repository arguments.")
    if args.summary and args.execute:
        parser.error("Summary is always read-only.")
    if not (args.summary or args.reevaluate or args.github_repo):
        parser.error("At least one --github-repo is required for a harvest plan.")
    try:
        if args.summary:
            _print(PublicCorpus(args.directory).summary())
            return 0
        if args.reevaluate:
            corpus = PublicCorpus(args.directory)
            if not args.execute:
                _print(
                    {
                        "mode": "public_reevaluation_preview",
                        "remote_requests": False,
                        "writes": False,
                        "summary": corpus.summary(),
                        "notice": PUBLIC_CORPUS_NOTICE,
                    }
                )
                return 0
            report = reevaluate_public_corpus(corpus)
            _print(report)
            return 3 if report.analysis_error_job_count else 0
        plan = preview_public_harvest(args.github_repo, runs_per_repository=args.per_repo)
        if not args.execute:
            _print(
                {
                    "mode": "public_harvest_preview",
                    "remote_requests": False,
                    "writes": False,
                    "plan": plan,
                    "notice": PUBLIC_CORPUS_NOTICE,
                }
            )
            return 0
        report = asyncio.run(
            harvest_public_repositories(
                args.github_repo,
                runs_per_repository=args.per_repo,
                corpus=PublicCorpus(args.directory),
            )
        )
        _print(report)
        return 0 if report.state == "complete" else 3
    except PublicCorpusError:
        _print(
            {
                "error": (
                    "Public corpus operation stopped safely; check the local store and public "
                    "API access."
                ),
                "notice": PUBLIC_CORPUS_NOTICE,
            }
        )
        return 2
    except KeyboardInterrupt:
        _print({"state": "interrupted", "notice": PUBLIC_CORPUS_NOTICE})
        return 130
    except Exception:
        # No exception message is surfaced because it could contain source/log material.
        _print({"error": "Unexpected local failure; sensitive details were omitted."})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
