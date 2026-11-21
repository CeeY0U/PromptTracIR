"""FastAPI backend for the analyst UI (`ptir serve CASE`).

v0.7: attack flow, filtered timeline with evidence states, evidence and custody, raw records,
STIX 2.1 export. The page loads Cytoscape from /static (vendored), so it works offline in the lab.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import views
from .case import Case

WEB = Path(__file__).parent / "web"


def create_app(case: Case) -> FastAPI:
    app = FastAPI(title="PromptTracIR")
    app.mount("/static", StaticFiles(directory=WEB / "vendor"), name="static")

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    @app.get("/api/case")
    def case_info():
        m = case.meta
        return {"name": m["name"], "created": m["created"], "envelope": m.get("envelope"),
                "evidence": [{"sha256": d, **i} for d, i in m["evidence"].items()]}

    def out(name):
        data = case.read_output(name)
        if data is None:
            raise HTTPException(404, f"{name} missing; run `ptir analyze` first")
        return data

    @app.get("/api/graph")
    def graph(view: str = "chain"):
        g = out("graph.json")
        if view == "chain":
            keep = set(out("chain.json").get("nodes") or [])
            if keep:
                g = {"nodes": [n for n in g["nodes"] if n["id"] in keep],
                     "edges": [e for e in g["edges"] if e["src"] in keep and e["dst"] in keep]}
        return g

    for name in ("findings", "impact", "attribution", "chain", "traceback", "tool_links", "crosscheck"):
        app.add_api_route(f"/api/{name}", (lambda n=name: out(f"{n}.json")), methods=["GET"])

    @app.get("/api/llm")
    def llm():
        return case.read_output("llm.json") or {}

    @app.get("/api/flow")
    def flow():
        return views.attack_flow(case)

    @app.get("/api/events/{event_id:path}")
    def event(event_id: str):
        ev = case.load_events("event_id = ?", [event_id])
        if not ev:
            raise HTTPException(404, "no such event")
        e = ev[0].model_dump(mode="json")
        info = case.meta["evidence"].get(e["raw"]["evidence_id"], {})
        e["raw"]["file"] = info.get("file")
        e["raw"]["original_path"] = info.get("original_path")
        return e

    @app.get("/api/raw/{event_id:path}")
    def raw(event_id: str):
        try:
            return views.raw_record(case, event_id)
        except KeyError:
            raise HTTPException(404, "no such event")

    @app.get("/api/timeline")
    def timeline(source: str | None = None, q: str | None = None, chain: bool = False, limit: int = 2000):
        return views.timeline(case, source=source, q=q, chain_only=chain, limit=min(limit, 20000))

    @app.get("/api/evidence")
    def evidence():
        return views.evidence(case)

    @app.post("/api/verify")
    def verify():
        res = case.verify_evidence()
        return {"ok": all(res.values()), "results": res}

    @app.get("/api/export/stix")
    def export_stix():
        from .stix import export_case
        try:
            bundle = export_case(case)
        except ValueError as e:
            raise HTTPException(404, str(e))
        name = f"{case.meta.get('name', 'case')}-stix.json"
        return Response(json.dumps(bundle, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    return app
