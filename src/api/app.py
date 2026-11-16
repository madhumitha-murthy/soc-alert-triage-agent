"""FastAPI service for the SOC alert triage agent."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader

from src.agents.schemas import AlertInput, TriageDecision
from src.agents.triage_agent import triage_alert

logger = logging.getLogger(__name__)

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_api_key(api_key: str | None = Security(_API_KEY_HEADER)):
    """Validate the API key if TRIAGE_API_KEY is configured."""
    expected = os.getenv("TRIAGE_API_KEY")
    if not expected:
        return  # No key configured — allow all (dev mode)
    if api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    yield


app = FastAPI(
    title="SOC Alert Triage Agent",
    description="LangGraph-powered security copilot that triages SOC alerts.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    """Health check for Docker/Kubernetes probes."""
    return {"status": "ok"}


@app.post("/triage", response_model=TriageDecision)
def triage(alert: AlertInput, _key=Depends(_verify_api_key)):
    """Triage a single SOC alert.

    Accepts an alert and returns a triage decision with label,
    severity, MITRE ATT&CK mapping, reasoning, and recommended action.
    """
    try:
        decision = triage_alert(alert)
    except Exception:
        logger.exception("Triage failed for alert %s", alert.alert_id)
        raise HTTPException(
            status_code=500, detail="Triage failed: internal error"
        )
    return decision


@app.post("/triage/batch", response_model=list[TriageDecision])
async def triage_batch(
    alerts: list[AlertInput], _key=Depends(_verify_api_key)
):
    """Triage a batch of alerts with bounded concurrency."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    if len(alerts) > 50:
        raise HTTPException(
            status_code=400, detail="Maximum 50 alerts per batch."
        )

    semaphore = asyncio.Semaphore(5)  # Max 5 concurrent LLM calls
    executor = ThreadPoolExecutor(max_workers=5)
    loop = asyncio.get_event_loop()

    async def _triage_one(alert: AlertInput) -> TriageDecision:
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(executor, triage_alert, alert),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Triage timed out for alert %s", alert.alert_id
                )
            except Exception:
                logger.exception(
                    "Triage failed for alert %s", alert.alert_id
                )
            return TriageDecision(
                alert_id=alert.alert_id,
                label="benign",
                confidence=0.0,
                reasoning="Triage error: manual review required.",
                recommended_action="Manual review required.",
            )

    decisions = await asyncio.gather(*[_triage_one(a) for a in alerts])
    return list(decisions)
