"""FastAPI backend for the analyst UI (`ptir serve CASE`)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .case import Case

WEB = Path(__file__).parent / "web"


def create_app(case: Case) -> FastAPI:
    app = FastAPI(title="PromptTracIR")

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

    for name in ("findings", "impact", "attribution", "chain", "traceback", "llm", "tool_links"):
        app.add_api_route(f"/api/{name}", (lambda n=name: out(f"{n}.json")), methods=["GET"])

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

    @app.get("/api/timeline")
    def timeline(limit: int = 2000):
        return [{"event_id": e.event_id, "ts": e.timestamp.isoformat(), "source": e.source.value,
                 "action": e.action.value, "pid": e.pid, "image": e.image,
                 "detail": e.command_line or e.object or e.attrs.get("text", "")[:160] or e.attrs.get("tool")}
                for e in case.load_events()[:limit]]

    return app
