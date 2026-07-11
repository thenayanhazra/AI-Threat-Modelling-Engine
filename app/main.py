from __future__ import annotations
import json
import os
import yaml
from defusedxml.common import DefusedXmlException
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from .engine import analyze
from .llm import enrich
from .models import SourceKind, ThreatModel
from .parsers import parse_input
from .report import render_pdf

app = FastAPI(title="AI Threat Modelling Engine", version="0.1.0", description="STRIDE and attack-path analysis from diagrams and infrastructure-as-code")

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))


async def bounded_read(file: UploadFile) -> bytes:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Upload exceeds {MAX_UPLOAD_BYTES} bytes")
    return data


@app.get("/health")
def health(): return {"status": "ok"}


@app.post("/v1/analyze", response_model=ThreatModel)
async def create_model(file: UploadFile = File(...), kind: SourceKind | None = Form(None), title: str = Form("Infrastructure Threat Model"), ai_enrichment: bool = Form(False)):
    try:
        model = analyze(parse_input(file.filename or "input", await bounded_read(file), kind, MAX_UPLOAD_BYTES), title)
        return await enrich(model) if ai_enrichment else model
    except (ValueError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, DefusedXmlException) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/report.pdf")
async def create_report(file: UploadFile = File(...), kind: SourceKind | None = Form(None), title: str = Form("Infrastructure Threat Model"), ai_enrichment: bool = Form(False)):
    try:
        model = analyze(parse_input(file.filename or "input", await bounded_read(file), kind, MAX_UPLOAD_BYTES), title)
        if ai_enrichment:
            model = await enrich(model)
        return Response(render_pdf(model), media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="threat-model.pdf"'})
    except (ValueError, UnicodeError, yaml.YAMLError, DefusedXmlException) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
