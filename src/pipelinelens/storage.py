"""Durable incident storage with a SQLite development path and PostgreSQL compatibility."""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from pipelinelens.domain import AnalysisSnapshot, KnowledgeDocument, SimilarIncident
from pipelinelens.services.analysis import stable_incident_id


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for PipelineLens operational records."""


class IncidentRecord(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "repository_external_id",
            "run_external_id",
            "job_external_id",
            name="uq_incident_source",
        ),
    )

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    repository_external_id: Mapped[str] = mapped_column(String(256), index=True)
    repository_name: Mapped[str] = mapped_column(String(512))
    run_external_id: Mapped[str] = mapped_column(String(256))
    job_external_id: Mapped[str] = mapped_column(String(256))
    job_name: Mapped[str] = mapped_column(String(512))
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    summary: Mapped[str] = mapped_column(Text)
    error_text: Mapped[str] = mapped_column(Text)
    resolution_status: Mapped[str] = mapped_column(String(64), default="new", index=True)
    confirmed_resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    evidence: Mapped[list[EvidenceRecord]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class EvidenceRecord(Base):
    __tablename__ = "evidence_chunks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), index=True)
    chunk_id: Mapped[str] = mapped_column(String(128))
    chunk_type: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    incident: Mapped[IncidentRecord] = relationship(back_populates="evidence")


class KnowledgeRecord(Base):
    __tablename__ = "knowledge_documents"

    document_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_label: Mapped[str] = mapped_column(String(256), index=True)
    source_path: Mapped[str] = mapped_column(String(1024))
    content: Mapped[str] = mapped_column(Text)
    private_scope: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


def _tokenize(content: str) -> Counter[str]:
    return Counter(re.findall(r"[a-z][a-z0-9_/-]{2,}", content.lower()))


def _hybrid_similarity(left: str, right: str) -> float:
    """A dependency-free lexical similarity fallback suitable for local development.

    PostgreSQL + pgvector can replace the semantic component later without changing callers.
    """

    left_tokens = _tokenize(left)
    right_tokens = _tokenize(right)
    if not left_tokens or not right_tokens:
        return 0.0
    intersection = sum(
        min(left_tokens[token], right_tokens[token])
        for token in left_tokens.keys() & right_tokens.keys()
    )
    union = sum((left_tokens | right_tokens).values())
    return intersection / union if union else 0.0


class IncidentStore:
    """Persist sanitized incident history and expose bounded historical retrieval."""

    def __init__(self, database_url: str) -> None:
        if database_url.startswith("sqlite:///"):
            database_path = database_url.removeprefix("sqlite:///")
            if database_path and database_path != ":memory:":
                Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        engine_options = {"connect_args": connect_args}
        if database_url == "sqlite:///:memory:":
            engine_options["poolclass"] = StaticPool
        self.engine = create_engine(database_url, **engine_options)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def save_snapshot(self, snapshot: AnalysisSnapshot) -> str:
        incident_id = stable_incident_id(snapshot.repository, snapshot.run, snapshot.job)
        with self.session_factory() as session:
            record = session.get(IncidentRecord, incident_id)
            fields = {
                "provider": str(snapshot.repository.provider),
                "repository_external_id": snapshot.repository.external_id,
                "repository_name": snapshot.repository.display_name,
                "run_external_id": snapshot.run.external_id,
                "job_external_id": snapshot.job.external_id,
                "job_name": snapshot.job.name,
                "fingerprint": snapshot.fingerprint.digest,
                "category": snapshot.fingerprint.category,
                "summary": snapshot.diagnosis.summary,
                "error_text": snapshot.fingerprint.normalized_message,
            }
            if record is None:
                record = IncidentRecord(incident_id=incident_id, **fields)
                session.add(record)
            else:
                for name, value in fields.items():
                    setattr(record, name, value)
                session.execute(
                    delete(EvidenceRecord).where(EvidenceRecord.incident_id == incident_id)
                )
            for chunk in snapshot.chunks:
                session.add(
                    EvidenceRecord(
                        incident_id=incident_id,
                        chunk_id=chunk.chunk_id,
                        chunk_type=chunk.chunk_type,
                        content=chunk.content,
                        line_start=chunk.line_start,
                        line_end=chunk.line_end,
                    )
                )
            session.commit()
        return incident_id

    def find_similar(
        self,
        snapshot: AnalysisSnapshot,
        *,
        exclude_incident_id: str | None = None,
        limit: int = 5,
    ) -> list[SimilarIncident]:
        query_text = "\n".join(
            [
                snapshot.fingerprint.normalized_message,
                *[chunk.content for chunk in snapshot.chunks[:3]],
            ]
        )
        with self.session_factory() as session:
            records = session.scalars(
                select(IncidentRecord).where(
                    IncidentRecord.provider == str(snapshot.repository.provider),
                    IncidentRecord.repository_external_id == snapshot.repository.external_id,
                )
            ).all()

        matches: list[SimilarIncident] = []
        for record in records:
            if record.incident_id == exclude_incident_id:
                continue
            score = _hybrid_similarity(query_text, f"{record.error_text}\n{record.summary}")
            if record.fingerprint == snapshot.fingerprint.digest:
                score = 1.0
            elif record.category == snapshot.fingerprint.category:
                score = max(score, 0.35)
            if score < 0.13:
                continue
            matches.append(
                SimilarIncident(
                    incident_id=record.incident_id,
                    fingerprint=record.fingerprint,
                    category=record.category,
                    summary=record.summary,
                    confirmed_resolution=record.confirmed_resolution
                    if record.resolution_status == "resolved"
                    else None,
                    similarity=min(score, 1.0),
                )
            )
        return sorted(
            matches,
            key=lambda item: (item.confirmed_resolution is not None, item.similarity),
            reverse=True,
        )[:limit]

    def record_feedback(
        self, incident_id: str, outcome: str, confirmed_resolution: str | None = None
    ) -> None:
        if outcome not in {"resolved", "not_useful", "needs_review"}:
            raise ValueError("Outcome must be resolved, not_useful, or needs_review.")
        with self.session_factory() as session:
            record = session.get(IncidentRecord, incident_id)
            if record is None:
                raise KeyError(f"Unknown incident: {incident_id}")
            record.resolution_status = outcome
            record.confirmed_resolution = (
                confirmed_resolution.strip() if confirmed_resolution else None
            )
            session.commit()

    def upsert_knowledge_document(
        self,
        *,
        source_label: str,
        source_path: str,
        content: str,
        private_scope: bool = True,
    ) -> str:
        document_id = (
            __import__("hashlib")
            .sha256(f"{source_label}:{source_path}:{content}".encode())
            .hexdigest()[:24]
        )
        with self.session_factory() as session:
            record = session.get(KnowledgeRecord, document_id)
            if record is None:
                session.add(
                    KnowledgeRecord(
                        document_id=document_id,
                        source_label=source_label,
                        source_path=source_path,
                        content=content,
                        private_scope=private_scope,
                    )
                )
            else:
                record.content = content
                record.private_scope = private_scope
            session.commit()
        return document_id

    def find_relevant_knowledge(
        self, query: str, *, include_private_context: bool = False, limit: int = 2
    ) -> list[KnowledgeDocument]:
        if not include_private_context:
            return []
        with self.session_factory() as session:
            records = session.scalars(
                select(KnowledgeRecord).where(KnowledgeRecord.private_scope.is_(True))
            ).all()
        documents = [
            KnowledgeDocument(
                document_id=record.document_id,
                source_label=record.source_label,
                source_path=record.source_path,
                content=record.content,
                similarity=_hybrid_similarity(query, record.content),
                private_scope=record.private_scope,
            )
            for record in records
        ]
        return sorted(documents, key=lambda item: item.similarity, reverse=True)[:limit]

    def list_clusters(self, limit: int = 20) -> list[dict[str, object]]:
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    IncidentRecord.fingerprint,
                    IncidentRecord.category,
                    func.count(IncidentRecord.incident_id).label("incident_count"),
                    func.max(IncidentRecord.updated_at).label("last_seen"),
                )
                .group_by(IncidentRecord.fingerprint, IncidentRecord.category)
                .order_by(func.count(IncidentRecord.incident_id).desc())
                .limit(limit)
            ).all()
        return [
            {
                "fingerprint": row.fingerprint,
                "category": row.category,
                "incident_count": row.incident_count,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in rows
        ]
