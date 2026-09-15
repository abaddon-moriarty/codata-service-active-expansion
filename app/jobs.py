"""
Stockage en mémoire des jobs de login Codata en cours (résolution reCAPTCHA
en tâche de fond). Séparé de SessionStore car un job n'a pas encore de
session_id tant que le login n'a pas abouti.

Railway coupe les requêtes HTTP après ~20-25s côté proxy, alors que la
résolution reCAPTCHA via Anti-Captcha peut prendre plus longtemps.
/codata/login retourne donc immédiatement un job_id et lance le travail
en tâche de fond ; Make interroge ensuite /codata/login/status en boucle
(polling) jusqu'à obtenir un résultat.
"""

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

JOB_TTL_SECONDS = 600  # 10 min, largement suffisant pour le polling


@dataclass
class LoginJob:
    job_id: str
    status: str = "processing"  # "processing" | "logged_in" | "2fa_required" | "error"
    session_id: Optional[str] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)


class JobStore:
    def __init__(self, ttl_seconds: int = JOB_TTL_SECONDS):
        self._jobs: dict[str, LoginJob] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def create(self) -> LoginJob:
        self._cleanup_expired()
        job = LoginJob(job_id=str(uuid.uuid4()))
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Optional[LoginJob]:
        self._cleanup_expired()
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **kwargs: Any) -> Optional[LoginJob]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            for key, value in kwargs.items():
                setattr(job, key, value)
            return job

    def _cleanup_expired(self) -> None:
        cutoff = time.time() - self._ttl
        with self._lock:
            expired = [jid for jid, j in self._jobs.items() if j.created_at < cutoff]
            for jid in expired:
                del self._jobs[jid]


jobs = JobStore()
