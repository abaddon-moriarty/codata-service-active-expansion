"""
Configuration du service, chargée depuis les variables d'environnement.
Sur Railway : Project -> Variables.
"""
import os

CODATA_USERNAME = os.environ.get("CODATA_USERNAME", "")
CODATA_PASSWORD = os.environ.get("CODATA_PASSWORD", "")
ANTICAPTCHA_API_KEY = os.environ.get("ANTICAPTCHA_API_KEY", "")

# Clé que Make.com doit envoyer dans le header "X-API-Key" pour appeler le service.
# Génère une valeur aléatoire (ex: `openssl rand -hex 32`) et mets-la aussi dans Make.
SERVICE_API_KEY = os.environ.get("SERVICE_API_KEY", "")

# Durée de vie max d'une session en mémoire (secondes) avant nettoyage automatique.
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "900"))  # 15 min

# Codata
CODATA_LOGIN_URL = "https://explorer.codata.eu/index.php?idlg=fr"
CODATA_CONNEXION_URL = "https://explorer.codata.eu/connexion.php"
CODATA_SEARCH_URL = "https://explorer.codata.eu/recherche-emplacements.php"
CODATA_GEO_URL = "https://explorer.codata.eu/recherche-critere-geographique.php"
CODATA_RUE_URL = "https://explorer.codata.eu/recherche-critere-rue.php"
RECAPTCHA_SITE_KEY = "6LdKJWckAAAAAAtvFJ4bX1qNvPTcXojzcZAwzuiu"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

REQUIRED_ENV_VARS = [
    "CODATA_USERNAME",
    "CODATA_PASSWORD",
    "ANTICAPTCHA_API_KEY",
    "SERVICE_API_KEY",
]


def check_env() -> list[str]:
    """Retourne la liste des variables d'environnement obligatoires manquantes."""
    missing = []
    for name in REQUIRED_ENV_VARS:
        if not os.environ.get(name):
            missing.append(name)
    return missing
