# Codata Scraping Service

Remplace le notebook Colab `sync_codata_make.ipynb`. Service HTTP (FastAPI) déployé sur
Railway, appelé directement par Make.com.
Cette nouvelle version permet de ne plus utiliser Google Colab et évite les problèmes liés à l'automatisation par mise à jour de fichiers txt ou json dans Drive.

## Flux (3 appels HTTP depuis Make, dans l'ordre)

```md
1. POST /codata/login
   Body: {"addresses": [{"Ville": "Paris", "Rue": "Rue de Rivoli"}, ...]}
   -> {"status": "logged_in", "session_id": "..."}      si pas de 2FA
   -> {"status": "2fa_required", "session_id": "..."}   si 2FA demandée

2. [uniquement si "2fa_required"]
   -> Le scénario Make "2FA webhook" existant va chercher le code dans Outlook (inchangé)
   POST /codata/2fa
   Body: {"session_id": "...", "code": "123456"}
   -> {"status": "logged_in"}

3. POST /codata/scrape
   Body: {"session_id": "..."}
   -> {"status": "success", "results": [...], "total_results": N,
       "processed_count": N, "failed": [...]}
```

Toutes les requêtes doivent inclure le header `X-API-Key: <SERVICE_API_KEY>`.

La session (cookies Codata) est gardée **en mémoire côté serveur** entre les 3 appels,
associée au `session_id`. Elle expire au bout de 15 min (`SESSION_TTL_SECONDS`) ou dès que
`/codata/scrape` a répondu. Si le service redémarre entre deux appels (déploiement Railway,
veille), la session est perdue : il faut relancer depuis `/codata/login`. Ce risque a été
accepté (pas de persistance disque en Phase 2).

## Déploiement sur Railway

1. Créer un compte Railway (côté client, comme convenu dans le devis).
2. Nouveau projet -> "Deploy from GitHub repo" (pousser ce dossier sur un repo), ou
   "Empty project" + Railway CLI (`railway up`) si pas de repo GitHub.
3. Railway détecte le `Dockerfile` automatiquement.
4. Dans **Variables**, renseigner (voir `.env.example`) :
   - `CODATA_USERNAME`, `CODATA_PASSWORD`
   - `ANTICAPTCHA_API_KEY`
   - `SERVICE_API_KEY` (générer avec `openssl rand -hex 32`)
   - `SESSION_TTL_SECONDS` (optionnel, défaut 900)
5. Une fois déployé, Railway donne une URL du type `https://xxxx.up.railway.app`.
6. Vérifier : `curl https://xxxx.up.railway.app/health` -> `{"ok": true, ...}`.

## Modification des scénarios Make

- **Scénario Codata (déclenché par webhook)** : remplacer le module qui écrivait
  `webhook_input_*.json` sur Drive par un module HTTP `POST {URL}/codata/login`.
  - Si `status = "logged_in"` -> passer directement au module `/codata/scrape`.
  - Si `status = "2fa_required"` -> router vers le scénario 2FA (cf. ci-dessous), avec le
    `session_id` transmis en donnée.
- **Scénario "2FA webhook" (lecture Outlook)** : à la fin, au lieu d'écrire
  `2fa_code_*.json` sur Drive, ajouter un module HTTP `POST {URL}/codata/2fa` avec
  `{"session_id": "<reçu du scénario précédent>", "code": "<code extrait de l'email>"}`.
  Puis enchaîner sur `POST {URL}/codata/scrape` avec le même `session_id`.
- Dans les deux cas, le module `/codata/scrape` renvoie directement les résultats en JSON
  dans la réponse HTTP — plus besoin de relire un fichier `webhook_output_*.json`, le
  module Make suivant peut directement traiter `results`.

## Développement local

```bash
pip install -r requirements.txt
export CODATA_USERNAME=... CODATA_PASSWORD=... ANTICAPTCHA_API_KEY=... SERVICE_API_KEY=test
uvicorn app.main:app --reload
```

Doc interactive : <http://localhost:8000/docs>

## Ce qui n'a pas été repris du notebook

- Le cache fichier par adresse (24h) et la liste de retry manuelle : ils géraient
  l'asynchronisme du polling de fichiers, plus nécessaires avec un flux HTTP synchrone.
  Si utile, un cache en mémoire (par adresse, TTL configurable) peut être ajouté facilement.
- Selenium / undetected_chromedriver / pyvirtualdisplay / webdriver_manager : ces imports
  étaient présents dans le notebook mais jamais utilisés (le login/scraping se fait en
  `requests` + `BeautifulSoup`). Le service n'a donc pas besoin de Chrome/Chromium.
