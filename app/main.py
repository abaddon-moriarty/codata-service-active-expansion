"""
Service HTTP remplaçant le notebook Colab pour le scraping Codata.

Flux Make.com :
  1. POST /codata/login   {"addresses": [{"Ville": "...", "Rue": "..."}]}
     -> {"status": "logged_in", "session_id": "..."}                (pas de 2FA)
     -> {"status": "2fa_required", "session_id": "..."}             (2FA demandée)
  2. [uniquement si 2fa_required] Le scénario Make "2FA webhook" va chercher le
     code dans Outlook, puis :
     POST /codata/2fa   {"session_id": "...", "code": "123456"}
     -> {"status": "logged_in"}
  3. POST /codata/scrape   {"session_id": "..."}
     -> {"status": "success", "results": [...], "processed_count": N, "failed": [...]}
  4. [optionnel, par adresse en échec avec raison "rue non reconnue"] après passage par
     le skill de désambiguisation et correction de l'adresse :
     POST /codata/retry   {"session_id": "...", "Ville": "...", "Rue": "..."}
     -> {"status": "success"|"warning"|"error", "results": [...]}
     La session reste valide tant qu'elle est utilisée (TTL glissant, cf. sessions.py) —
     /codata/scrape ne la supprime plus automatiquement, pour permettre ce retry sans
     relancer tout le login/2FA.

Toute réponse d'erreur renvoie un code HTTP 4xx/5xx avec {"detail": "..."}.
"""

import logging
import threading

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.codata_client import (
    CodataError,
    scrape_address,
    scrape_all,
    start_login,
    submit_2fa_code,
)
from app.config import (
    ANTICAPTCHA_API_KEY,
    CODATA_PASSWORD,
    CODATA_USERNAME,
    SERVICE_API_KEY,
    check_env,
)
from app.jobs import jobs
from app.sessions import store

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("codata-service")

app = FastAPI(title="Codata Scraping Service", version="1.0.0")


# ── Auth ─────────────────────────────────────────────────────────────────────


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not SERVICE_API_KEY:
        # Pas de clé configurée -> le service refuse de démarrer "ouvert" par erreur.
        raise HTTPException(
            status_code=500, detail="SERVICE_API_KEY non configurée côté serveur."
        )
    if x_api_key != SERVICE_API_KEY:
        raise HTTPException(
            status_code=401, detail="Clé API invalide ou manquante (header X-API-Key)."
        )


# ── Schémas ──────────────────────────────────────────────────────────────────


class Address(BaseModel):
    Ville: str
    Rue: str = ""


class LoginRequest(BaseModel):
    addresses: list[Address] = Field(default_factory=list)


class TwoFARequest(BaseModel):
    session_id: str
    code: str


class ScrapeRequest(BaseModel):
    session_id: str


class RetryRequest(BaseModel):
    session_id: str
    Ville: str
    Rue: str = ""


# ── Endpoints ────────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    missing = check_env()
    return {"ok": not missing, "missing_env_vars": missing}


def _run_login(job_id: str, addresses_dicts: list[dict]) -> None:
    """Exécuté en tâche de fond : la partie longue (reCAPTCHA) qui causait
    les timeouts côté proxy Railway."""
    try:
        result = start_login(CODATA_USERNAME, CODATA_PASSWORD, ANTICAPTCHA_API_KEY)
    except CodataError as e:
        jobs.update(job_id, status="error", error=str(e))
        return

    entry = store.create(http_session=result["session"], addresses=addresses_dicts)

    if result["outcome"] == "2fa_required":
        store.update(entry.session_id, hidden_2fa_fields=result["hidden_2fa_fields"])
        jobs.update(job_id, status="2fa_required", session_id=entry.session_id)
        return

    store.update(entry.session_id, status="logged_in")
    jobs.update(job_id, status="logged_in", session_id=entry.session_id)


@app.post("/codata/login", dependencies=[Depends(require_api_key)])
def login(payload: LoginRequest):
    if not payload.addresses:
        raise HTTPException(status_code=400, detail="Aucune adresse fournie.")

    addresses_dicts = [a.model_dump() for a in payload.addresses]
    job = jobs.create()

    threading.Thread(
        target=_run_login, args=(job.job_id, addresses_dicts), daemon=True
    ).start()

    return {"job_id": job.job_id, "status": "processing"}


@app.get("/codata/login/status", dependencies=[Depends(require_api_key)])
def login_status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_id inconnu ou expiré.")

    response = {"status": job.status}
    if job.session_id:
        response["session_id"] = job.session_id
    if job.status == "error" and job.error:
        response["detail"] = job.error
    return response


@app.post("/codata/2fa", dependencies=[Depends(require_api_key)])
def submit_2fa(payload: TwoFARequest):
    entry = store.get(payload.session_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Session inconnue ou expirée. Relancer /codata/login.",
        )
    if entry.status != "awaiting_2fa":
        raise HTTPException(
            status_code=409,
            detail=f"Session dans l'état '{entry.status}', pas en attente de 2FA.",
        )

    try:
        submit_2fa_code(entry.http_session, entry.hidden_2fa_fields or {}, payload.code)
    except CodataError as e:
        store.update(entry.session_id, status="error", error=str(e))
        raise HTTPException(status_code=502, detail=str(e)) from e

    store.update(entry.session_id, status="logged_in")
    return {"status": "logged_in"}


@app.post("/codata/scrape", dependencies=[Depends(require_api_key)])
def scrape(payload: ScrapeRequest):
    entry = store.get(payload.session_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Session inconnue ou expirée. Relancer /codata/login.",
        )
    if entry.status != "logged_in":
        raise HTTPException(
            status_code=409,
            detail=f"Session dans l'état '{entry.status}', pas prête pour le scraping.",
        )

    outcome = scrape_all(entry.http_session, entry.addresses)
    # La session reste ouverte (TTL glissant) pour permettre un /codata/retry ciblé
    # après désambiguisation, sans relancer tout le login/2FA.

    status = (
        "success"
        if outcome["results"]
        else ("warning" if outcome["processed_count"] > 0 else "error")
    )
    return {
        "status": status,
        "results": outcome["results"],
        "total_results": len(outcome["results"]),
        "processed_count": outcome["processed_count"],
        "failed": outcome["failed"],
    }


@app.post("/codata/retry", dependencies=[Depends(require_api_key)])
def retry(payload: RetryRequest):
    """Retente UNE adresse (typiquement après correction via le skill de désambiguisation)
    sur une session déjà connectée, sans repasser par login/2FA."""
    entry = store.get(payload.session_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Session inconnue ou expirée. Relancer /codata/login.",
        )
    if entry.status != "logged_in":
        raise HTTPException(
            status_code=409,
            detail=f"Session dans l'état '{entry.status}', pas prête pour le scraping.",
        )

    try:
        results = scrape_address(entry.http_session, payload.Ville, payload.Rue)
    except CodataError as e:
        return {"status": "error", "results": [], "total_results": 0, "reason": str(e)}

    for result in results:
        result["ville_originale"] = payload.Ville
        result["rue_originale"] = payload.Rue

    status = "success" if results else "warning"
    return {"status": status, "results": results, "total_results": len(results)}
