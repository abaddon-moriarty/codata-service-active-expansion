"""
Stockage en mémoire des sessions Codata en cours entre les appels HTTP
(/login -> /2fa -> /scrape -> /retry...). Pas de persistance disque : si le
service redémarre, la session est perdue et il faut relancer depuis /login
(risque accepté, cf. échanges avec Marine).

TTL glissant : chaque utilisation de la session (get) repousse son
expiration, plutôt que de compter depuis la création. Ça laisse le temps
au skill de désambiguisation de tourner (et éventuellement à un humain de
valider une adresse corrigée) sans risquer que la session expire entre
deux appels /codata/retry.
"""

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from app.config import SESSION_TTL_SECONDS


@dataclass
class CodataSession:
    session_id: str
    http_session: requests.Session
    addresses: list[dict]
    status: str  # "awaiting_2fa" | "logged_in" | "error"
    last_used_at: float = field(default_factory=time.time)
    # Champs cachés du formulaire 2FA (récupérés au login, réutilisés à /2fa)
    hidden_2fa_fields: Optional[dict] = None
    error: Optional[str] = None


class SessionStore:
    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS):
        self._sessions: dict[str, CodataSession] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def create(
        self, http_session: requests.Session, addresses: list[dict]
    ) -> CodataSession:
        self._cleanup_expired()
        session_id = str(uuid.uuid4())
        entry = CodataSession(
            session_id=session_id,
            http_session=http_session,
            addresses=addresses,
            status="awaiting_2fa",
        )
        with self._lock:
            self._sessions[session_id] = entry
        return entry

    def get(self, session_id: str) -> Optional[CodataSession]:
        self._cleanup_expired()
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry:
                entry.last_used_at = time.time()
            return entry

    def update(self, session_id: str, **kwargs: Any) -> Optional[CodataSession]:
        with self._lock:
            entry = self._sessions.get(session_id)
            if not entry:
                return None
            for key, value in kwargs.items():
                setattr(entry, key, value)
            entry.last_used_at = time.time()
            return entry

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def _cleanup_expired(self) -> None:
        cutoff = time.time() - self._ttl
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items() if s.last_used_at < cutoff
            ]
            for sid in expired:
                del self._sessions[sid]


store = SessionStore()
