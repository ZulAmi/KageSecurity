import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.db import init_db
from api.routes import scans, reports
from api import scanner_bridge


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scanner_bridge.set_event_loop(asyncio.get_event_loop())
    yield


app = FastAPI(
    title="KageSec API",
    description="AI-powered web application security scanner — OWASP Top 10, HIPAA, GDPR, ISO 27001, APPI",
    version="0.2.0",
    lifespan=lifespan,
)

_CORS_ORIGINS = [o.strip() for o in os.getenv(
    "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}
