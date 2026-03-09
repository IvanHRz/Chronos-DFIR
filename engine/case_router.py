"""
Chronos-DFIR Case Management API Router.

FastAPI APIRouter for case CRUD, phases, files, journal, IOCs, and narrative.
Mounted in app.py via app.include_router(case_router).
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from engine import case_db

logger = logging.getLogger("chronos.cases")

case_router = APIRouter(prefix="/api/cases", tags=["cases"])


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CreateCaseRequest(BaseModel):
    name: str
    description: str = ""
    investigator: str = ""


class UpdateCaseRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    investigator: Optional[str] = None
    status: Optional[str] = None


class CreatePhaseRequest(BaseModel):
    title: str
    objective: str = ""
    phase_number: Optional[int] = None


class UpdatePhaseRequest(BaseModel):
    title: Optional[str] = None
    objective: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None


class JournalEntryRequest(BaseModel):
    content: str
    entry_type: str = "note"
    author: str = "investigator"
    phase_id: Optional[str] = None


class NarrativeRequest(BaseModel):
    content_md: str
    version: int = 1


# ---------------------------------------------------------------------------
# Case Endpoints
# ---------------------------------------------------------------------------

@case_router.post("")
async def create_case(request: CreateCaseRequest):
    """Create a new investigation case."""
    try:
        case_id = case_db.create_case(
            name=request.name,
            description=request.description,
            investigator=request.investigator,
        )
        logger.info(f"Case created: {request.name} ({case_id})")
        return {"case_id": case_id, "name": request.name, "status": "open"}
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.get("")
async def list_cases(status: Optional[str] = None):
    """List all cases, optionally filtered by status."""
    try:
        cases = case_db.list_cases(status_filter=status)
        return {"cases": cases, "total": len(cases)}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.get("/{case_id}")
async def get_case(case_id: str):
    """Get a single case with phase and file counts."""
    try:
        case = case_db.get_case(case_id)
        if case is None:
            return JSONResponse(content={"error": "Case not found"}, status_code=404)
        # Include phases
        case["phases"] = case_db.get_phases(case_id)
        return case
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.put("/{case_id}")
async def update_case(case_id: str, request: UpdateCaseRequest):
    """Update case metadata."""
    try:
        fields = {k: v for k, v in request.model_dump().items() if v is not None}
        if not fields:
            return JSONResponse(content={"error": "No fields to update"}, status_code=400)
        case_db.update_case(case_id, **fields)
        return {"status": "updated", "case_id": case_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.delete("/{case_id}")
async def delete_case(case_id: str):
    """Archive (soft-delete) a case."""
    try:
        case_db.delete_case(case_id)
        return {"status": "archived", "case_id": case_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# Phase Endpoints
# ---------------------------------------------------------------------------

@case_router.post("/{case_id}/phases")
async def create_phase(case_id: str, request: CreatePhaseRequest):
    """Create a new investigation phase within a case."""
    try:
        phase_id = case_db.create_phase(
            case_id=case_id,
            title=request.title,
            objective=request.objective,
            phase_number=request.phase_number,
        )
        logger.info(f"Phase created: {request.title} in case {case_id}")
        return {"phase_id": phase_id, "title": request.title, "case_id": case_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.get("/{case_id}/phases")
async def get_phases(case_id: str):
    """List all phases for a case with file counts."""
    try:
        phases = case_db.get_phases(case_id)
        return {"phases": phases, "total": len(phases)}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.put("/{case_id}/phases/{phase_id}")
async def update_phase(case_id: str, phase_id: str, request: UpdatePhaseRequest):
    """Update phase metadata."""
    try:
        fields = {k: v for k, v in request.model_dump().items() if v is not None}
        if not fields:
            return JSONResponse(content={"error": "No fields to update"}, status_code=400)
        case_db.update_phase(phase_id, **fields)
        return {"status": "updated", "phase_id": phase_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# File Endpoints
# ---------------------------------------------------------------------------

@case_router.get("/{case_id}/files")
async def get_case_files(case_id: str, phase_id: Optional[str] = None):
    """Get all files for a case, optionally filtered by phase."""
    try:
        files = case_db.get_case_files(case_id, phase_id=phase_id)
        return {"files": files, "total": len(files)}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# Journal Endpoints
# ---------------------------------------------------------------------------

@case_router.post("/{case_id}/journal")
async def add_journal_entry(case_id: str, request: JournalEntryRequest):
    """Add a journal entry (note, finding, or AI insight)."""
    try:
        entry_id = case_db.add_journal_entry(
            case_id=case_id,
            content=request.content,
            entry_type=request.entry_type,
            author=request.author,
            phase_id=request.phase_id,
        )
        return {"entry_id": entry_id, "case_id": case_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.get("/{case_id}/journal")
async def get_journal(case_id: str, phase_id: Optional[str] = None):
    """Get journal entries for a case."""
    try:
        entries = case_db.get_journal(case_id, phase_id=phase_id)
        return {"entries": entries, "total": len(entries)}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# IOC Endpoints
# ---------------------------------------------------------------------------

@case_router.get("/{case_id}/iocs")
async def get_case_iocs(case_id: str, phase_id: Optional[str] = None):
    """Get aggregated IOCs for a case."""
    try:
        iocs = case_db.get_case_iocs(case_id, phase_id=phase_id)
        # Group by type for summary
        by_type: Dict[str, int] = {}
        for ioc in iocs:
            by_type[ioc["ioc_type"]] = by_type.get(ioc["ioc_type"], 0) + 1
        return {"iocs": iocs, "total": len(iocs), "by_type": by_type}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ---------------------------------------------------------------------------
# Narrative Endpoints
# ---------------------------------------------------------------------------

@case_router.get("/{case_id}/narrative")
async def get_narrative(case_id: str):
    """Get the current investigation narrative."""
    try:
        narrative = case_db.get_narrative(case_id)
        if narrative is None:
            return {"narrative": None, "case_id": case_id}
        return narrative
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@case_router.put("/{case_id}/narrative")
async def update_narrative(case_id: str, request: NarrativeRequest):
    """Save or update the investigation narrative."""
    try:
        narrative_id = case_db.save_narrative(
            case_id=case_id,
            content_md=request.content_md,
            version=request.version,
        )
        return {"narrative_id": narrative_id, "case_id": case_id, "status": "saved"}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
