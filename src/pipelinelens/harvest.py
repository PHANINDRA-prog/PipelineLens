"""Opt-in failed-pipeline corpus CLI. Preview is offline and writes nothing.

``python -m pipelinelens.harvest --project group/a --project group/b
--project group/c --per-project 75 --execute`` collects up to 225 distinct recent
failed pipelines. Repeat the same command to resume; completed samples are reused.
``python -m pipelinelens.harvest --reevaluate --execute`` reclassifies retained logs
without ANY remote calls. Omit ``--execute`` for a local-only reevaluation plan.
``--summary`` reads local coverage only. Tokens are accepted ONLY through existing
``get_settings`` configuration, never from a CLI argument or printed in output.

Exit codes: 0 successful plan/summary/completed batch; 2 controlled error;
3 incomplete batch (including rate limiting or insufficient distinct pipelines);
130 interrupted. JSON stdout is bounded metadata/excerpts, never full traces.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from pipelinelens.config import get_settings
from pipelinelens.services.pipeline_corpus import (
    CorpusError,
    PipelineCorpus,
    harvest_pipelines,
    preview_harvest,
    reevaluate_corpus,
    rule_checksum,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes arbitrary argv, potentially including a token.
        del message
        self.exit(2, "Invalid arguments. Use --help; credentials are configuration-only.\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Return an exit status. Only --execute enables collection or reevaluation writes."""

    parser = _Parser(description="Retain sanitized failed-pipeline observations, not ML training.")
    parser.add_argument(
        "--project", action="append", default=[], help="GitLab project path; repeat.",
    )
    parser.add_argument(
        "--per-project", type=int, default=75, help="Latest failed pipelines (1-500).",
    )
    parser.add_argument("--concurrency", type=int, choices=(2, 3), default=2)
    parser.add_argument(
        "--directory", type=Path, help="Local corpus directory; default data/corpus.",
    )
    parser.add_argument("--execute", action="store_true", help="Explicitly enable local writes.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--reevaluate", action="store_true", help="Offline reclassification only.")
    mode.add_argument("--summary", action="store_true", help="Read retained local coverage only.")
    args = parser.parse_args(argv)
    if ((args.reevaluate or args.summary) and args.project) or (args.summary and args.execute):
        parser.error("Incompatible modes.")
    if not (args.reevaluate or args.summary or args.project):
        parser.error("At least one project is required for a harvest plan.")
    try:
        settings = get_settings()
        corpus = PipelineCorpus(args.directory, settings=settings)
        if args.summary:
            print(corpus.summary().model_dump_json(indent=2))
            return 0
        if args.reevaluate:
            if args.execute:
                report = reevaluate_corpus(corpus)
                print(report.model_dump_json(indent=2))
                return 3 if report.analysis_error_job_count else 0
            print(json.dumps({
                "mode": "reevaluation_preview", "remote_requests": False, "writes": False,
                "rule_checksum": rule_checksum(),
                "summary": corpus.summary().model_dump(mode="json"),
            }, indent=2))
            return 0
        plan = preview_harvest(
            settings, args.project, per_project=args.per_project, concurrency=args.concurrency,
        )
        if not args.execute:
            print(json.dumps({
                "mode": "harvest_preview", "remote_requests": False, "writes": False,
                "plan": plan.model_dump(mode="json"),
            }, indent=2))
            return 0
        report = asyncio.run(harvest_pipelines(
            settings, args.project, per_project=args.per_project, concurrency=args.concurrency,
            corpus=corpus,
        ))
        print(report.model_dump_json(indent=2))
        return 0 if report.target_met else 3
    except CorpusError:
        # No arbitrary exception body, token, URL query, local path or raw trace escapes.
        print(json.dumps({
            "error": "Corpus operation failed safely. Check configuration, capacity and local "
                     "store integrity. Existing committed observations were not replaced.",
        }))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({
            "state": "interrupted", "message": "Completed job checkpoints retained.",
        }))
        return 130
    except Exception:
        print(json.dumps({"error": "Unexpected local failure; sensitive error details omitted."}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())