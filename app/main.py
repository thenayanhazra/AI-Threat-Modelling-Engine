from __future__ import annotations
import json
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from .engine import analyze
from .models import SourceKind, ThreatModel
from .parsers import parse_input
from .report import render_pdf

app = FastAPI(title="AI Threat Modelling Engine", version="0.1.0", description="STRIDE and attack-path analysis from diagrams and infrastructure-as-code")


@app.get("/health")
def health(): return {"status": "ok"}


@app.post("/v1/analyze", response_model=ThreatModel)
async def create_model(file: UploadFile = File(...), kind: SourceKind | None = Form(None), title: str = Form("Infrastructure Threat Model")):
    try:
        return analyze(parse_input(file.filename or "input", await file.read(), kind), title)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/report.pdf")
async def create_report(file: UploadFile = File(...), kind: SourceKind | None = Form(None), title: str = Form("Infrastructure Threat Model")):
    try:
        model = analyze(parse_input(file.filename or "input", await file.read(), kind), title)
        return Response(render_pdf(model), media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="threat-model.pdf"'})
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
