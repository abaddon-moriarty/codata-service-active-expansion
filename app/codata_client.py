"""
Logique de connexion et scraping Codata.
Reprise quasi telle quelle depuis sync_codata_make.ipynb, avec deux changements :
  - plus d'écriture/lecture de fichiers (Drive) : les échanges se font en mémoire.
  - la 2FA n'est plus attendue par polling : le service retourne "awaiting_2fa"
    et c'est un second appel HTTP (/codata/2fa) qui apporte le code.
"""

import logging
import random
import re
import time
import urllib.parse
from datetime import datetime
from typing import Optional
from urllib.parse import parse_qs, urlparse

import requests
from anticaptchaofficial.recaptchav3proxyless import recaptchaV3Proxyless
from bs4 import BeautifulSoup

from app.config import (
    CODATA_CONNEXION_URL,
    CODATA_GEO_URL,
    CODATA_LOGIN_URL,
    CODATA_RUE_URL,
    CODATA_SEARCH_URL,
    RECAPTCHA_SITE_KEY,
    USER_AGENT,
)

logger = logging.getLogger("codata")

# Codata affiche 75 résultats par page. On plafonne le nombre de pages récupérées pour
# éviter une recherche qui dérape (ex. une ville entière mal filtrée malgré tout).
PAGE_SIZE = 75
MAX_PAGES = 15  # jusqu'à ~1125 résultats par adresse


def _extract_pagination(soup: BeautifulSoup) -> tuple[Optional[str], int]:
    """Cherche les liens de pagination (ex. <a href=".../recherche-emplacements.php?sid=5579325&page=2">)
    pour en tirer le sid de session Codata et le numéro de la dernière page.
    S'il n'y a pas de liens de pagination, la recherche tient sur une seule page."""
    sid = None
    max_page = 1
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "page=" not in href:
            continue
        qs = parse_qs(urlparse(href).query)
        for page_val in qs.get("page", []):
            try:
                max_page = max(max_page, int(page_val))
            except ValueError:
                pass
        if not sid:
            sid_vals = qs.get("sid")
            if sid_vals:
                sid = sid_vals[0]
    return sid, max_page


def _fetch_results_page(
    session: requests.Session, sid: str, page: int
) -> requests.Response:
    url = f"{CODATA_SEARCH_URL}?sid={sid}&page={page}"
    headers = {"Referer": CODATA_SEARCH_URL, "User-Agent": USER_AGENT}
    return session.get(url, headers=headers, timeout=30)


class CodataError(Exception):
    """Erreur métier attendue (identifiants invalides, captcha refusé, etc.)."""


class StreetNotRecognizedError(CodataError):
    """La rue demandée n'a pas été reconnue par Codata — on refuse le fallback ville entière
    (coûteux, surtout sur une grande ville) et on marque l'adresse en échec à la place."""


def create_robust_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )
    return session


def start_login(username: str, password: str, anticaptcha_api_key: str) -> dict:
    """
    Étape 1/2 : soumet identifiants + reCAPTCHA à Codata.
    Retourne un dict :
      {"outcome": "success", "session": <requests.Session>}
      {"outcome": "2fa_required", "session": ..., "hidden_2fa_fields": {...}}
    Lève CodataError si identifiants/captcha refusés ou erreur inattendue.
    """
    session = create_robust_session()

    login_page = session.get(CODATA_LOGIN_URL, timeout=30)
    soup = BeautifulSoup(login_page.text, "html.parser")
    form = soup.find("form", {"name": "connexion"})
    if not form:
        raise CodataError(
            "Formulaire de connexion Codata introuvable (le site a peut-être changé)."
        )

    login_data = {
        inp.get("name"): inp.get("value", "")
        for inp in form.find_all("input")
        if inp.get("name")
    }
    login_data["identifiant"] = username
    login_data["motdepasse"] = password

    logger.info("Résolution reCAPTCHA via Anti-Captcha...")
    solver = recaptchaV3Proxyless()
    solver.set_verbose(0)
    solver.set_key(anticaptcha_api_key)
    solver.set_website_url(CODATA_LOGIN_URL)
    solver.set_website_key(RECAPTCHA_SITE_KEY)
    solver.set_page_action("login")
    solver.set_min_score(0.7)

    token = solver.solve_and_return_solution()
    if not token:
        raise CodataError(f"Échec résolution Anti-Captcha : {solver.error_code}")
    login_data["recaptcha_token"] = token

    action_url = form.get("action", "connexion.php")
    if not action_url.startswith("http"):
        action_url = urllib.parse.urljoin(CODATA_LOGIN_URL, action_url)

    response = session.post(
        action_url, data=login_data, timeout=30, allow_redirects=True
    )
    page_text = response.text.lower()

    if "recaptcha_failed" in page_text:
        raise CodataError("reCAPTCHA rejeté par Codata (score trop bas).")

    if "combinaison identifiant / mot de passe" in page_text:
        raise CodataError("Identifiants Codata incorrects.")

    if "code d'authentification" in page_text and "connexion-token" in page_text:
        logger.info("2FA demandée par Codata.")
        soup2 = BeautifulSoup(response.text, "html.parser")
        form2 = soup2.find("form", {"name": "connexion-token"})
        if not form2:
            raise CodataError("Formulaire 2FA introuvable dans la réponse Codata.")
        hidden_data = {
            inp.get("name"): inp.get("value", "")
            for inp in form2.find_all("input", type="hidden")
            if inp.get("name")
        }
        return {
            "outcome": "2fa_required",
            "session": session,
            "hidden_2fa_fields": hidden_data,
        }

    if (
        "déconnexion" in page_text
        or "mon-compte" in page_text
        or "deconnexion.php" in page_text
        or "dashboard.php" in response.url
    ):
        logger.info("Connexion Codata réussie sans 2FA.")
        return {"outcome": "success", "session": session}

    raise CodataError(
        "Réponse Codata non reconnue au login (le site a peut-être changé)."
    )


def submit_2fa_code(session: requests.Session, hidden_fields: dict, code: str) -> None:
    """Étape 2/2 : soumet le code 2FA reçu par email. Lève CodataError si échec."""
    code = code.strip()
    logger.info(
        "Soumission code 2FA (longueur=%d, champs cachés=%s)",
        len(code),
        list(hidden_fields.keys()),
    )

    verify_response = session.get(
        CODATA_CONNEXION_URL,
        params={"token": code, **hidden_fields},
        timeout=30,
        allow_redirects=True,
    )

    logger.info(
        "Vérification 2FA — status=%s, url finale=%s",
        verify_response.status_code,
        verify_response.url,
    )

    success = (
        "dashboard.php" in verify_response.url
        or "deconnexion.php" in verify_response.text.lower()
    )
    if not success:
        logger.info(
            "Extrait réponse (600 premiers caractères) :\n%s",
            verify_response.text[:600],
        )
        raise CodataError("Code 2FA refusé par Codata.")
    logger.info("Connexion Codata avec 2FA réussie.")


# ── Recherche / scraping ────────────────────────────────────────────────────


def _validate_search_criteria(session: requests.Session, ville: str, rue: str):
    validated_ville = None
    code_geo = None

    if ville:
        geo_params = {
            "w": "1108",
            "criteregeographique": ville.lower(),
            "universe": "emplacements",
        }
        geo_headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": CODATA_SEARCH_URL,
            "Origin": "https://explorer.codata.eu",
        }
        geo_response = session.post(
            CODATA_GEO_URL, data=geo_params, headers=geo_headers, timeout=30
        )
        logger.info(
            "Validation ville '%s' — status=%s, réponse: %s",
            ville,
            geo_response.status_code,
            geo_response.text[:800],
        )
        if not geo_response.ok:
            return None, None
        geo_json = geo_response.json()
        if geo_json.get("success") and geo_json.get("critere_geographique"):
            candidates = geo_json["critere_geographique"]
            # Codata renvoie plusieurs niveaux géographiques (Département, Commune, Unité
            # Urbaine...) pour un même nom. On préfère la Commune (niveau_geo=5), qui est
            # ce qu'utilise la recherche manuelle sur le site ; sinon on retombe sur le
            # premier résultat.
            commune = next((c for c in candidates if c.get("niveau_geo") == 5), None)
            first_result = commune or candidates[0]
            validated_ville = first_result["id"]
            code_geo = first_result["code_geo"]
            logger.info(
                "Ville validée: %s (code_geo=%s) — %d résultat(s) candidats",
                validated_ville,
                code_geo,
                len(candidates),
            )
        else:
            logger.info("Aucun résultat de validation pour la ville '%s'", ville)
            return None, None

    validated_rue = None
    if rue and code_geo:
        rue_params = {
            "w": "1108",
            "critererue": rue.lower(),
            "universe": "emplacements",
            "niveau_geo": "5",
            "code_geo": code_geo,
        }
        rue_headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": CODATA_SEARCH_URL,
            "Origin": "https://explorer.codata.eu",
        }
        rue_response = session.post(
            CODATA_RUE_URL, data=rue_params, headers=rue_headers, timeout=30
        )
        logger.info(
            "Validation rue '%s' (code_geo=%s) — status=%s, réponse: %s",
            rue,
            code_geo,
            rue_response.status_code,
            rue_response.text[:800],
        )
        if rue_response.ok:
            rue_json = rue_response.json()
            if rue_json.get("success") and rue_json.get("critere_rue"):
                validated_rue = rue_json["critere_rue"][0]["id"]
                logger.info("Rue validée: %s", validated_rue)
            else:
                logger.info(
                    "Aucun résultat de validation pour la rue '%s' avec code_geo=%s",
                    rue,
                    code_geo,
                )

    return validated_ville, validated_rue


def _submit_search(
    session: requests.Session, ville: str, rue: str
) -> Optional[requests.Response]:
    validated_ville, validated_rue = _validate_search_criteria(session, ville, rue)
    if not validated_ville:
        return None

    if rue and not validated_rue:
        raise StreetNotRecognizedError(
            f"Rue '{rue}' non reconnue par Codata pour '{ville}' — recherche annulée "
            f"(pas de fallback ville entière, trop coûteux sur une grande ville)."
        )

    search_page = session.get(CODATA_SEARCH_URL, timeout=30)
    soup = BeautifulSoup(search_page.text, "html.parser")
    csrf_input = soup.find("input", {"name": "_csrf_token"})
    csrf_token = csrf_input.get("value", "") if csrf_input else ""

    form_data = {
        "_csrf_token": csrf_token,
        "form-criteregeographique": validated_ville,
        "form-rue": validated_rue or "",
        "form-numero": "",
        "form-retailer-commerce": "",
        "form-activite": "",
        "form-estretailer": "null",
        "form-estsuccursale": "null",
        "form-estnouveaucommerce": "null",
        "form-codeemplacement": "",
        "form-proprietaire": "",
        "form-urbain": "",
        "form-peripherique": "",
        "form-piedimmeuble": "",
        "form-zonecommerciale": "",
        "form-centrecommercial": "",
        "form-outletcenter": "",
        "form-gareaeroport": "",
        "form-retailpark": "",
        "form-galeriemarchande": "",
        "form-halle": "",
        "form-perimetrecodata": "null",
        "form-populationgeographique": "ville",
        "form-populationnombremin": "",
        "form-populationnombremax": "",
        "form-revenugeographique": "ville",
        "form-revenumoyenmin": "",
        "form-revenumoyenmax": "",
        "form-emplacementnombremin": "",
        "form-emplacementnombremax": "",
        "form-retailernombremin": "",
        "form-retailernombremax": "",
        "form-retailerpctnombremin": "",
        "form-retailerpctnombremax": "",
        "form-prestataireindex": "",
        "form-nomprestataire": "",
        "form-opportunitescodata": "",
        "form-opportunitesexternes": "",
        "form-datedetection": "1_semaine",
        "rechercher": "Rechercher",
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://explorer.codata.eu",
        "Referer": CODATA_SEARCH_URL,
        "User-Agent": USER_AGENT,
    }

    response = session.post(
        CODATA_SEARCH_URL,
        data=form_data,
        headers=headers,
        allow_redirects=False,
        timeout=30,
    )

    if response.status_code == 302:
        redirect_url = response.headers.get("Location", "")
        if not redirect_url.startswith("http"):
            base_url = "https://explorer.codata.eu"
            redirect_url = (
                f"{base_url}{redirect_url}"
                if redirect_url.startswith("/")
                else f"{base_url}/{redirect_url}"
            )
        time.sleep(1)
        final_response = session.get(
            redirect_url,
            headers={"Referer": CODATA_SEARCH_URL, "User-Agent": USER_AGENT},
            timeout=30,
        )
        return final_response if final_response.ok else None

    if response.status_code == 200:
        return response

    return None


def _separer_adresse(adresse_complete: str) -> dict:
    resultat = {"numero": "", "rue": "", "code_postal": "", "ville": ""}
    if not adresse_complete or not isinstance(adresse_complete, str):
        return resultat

    adresse = adresse_complete.strip()
    pattern = r"^(?P<numero>[\d\-]+\w*)?\s*,?\s*(?P<rue>.+?)\s*,\s*(?P<code_postal>\d{5})\s*(?P<ville>.+)$"
    match = re.match(pattern, adresse)

    if match:
        resultat["numero"] = match.group("numero") or ""
        resultat["rue"] = match.group("rue") or ""
        resultat["code_postal"] = match.group("code_postal") or ""
        resultat["ville"] = match.group("ville") or ""
    else:
        parties = adresse.rsplit(",", 1)
        if len(parties) == 2:
            resultat["rue"] = parties[0].strip()
            ville_partie = parties[1].strip()
            code_ville_match = re.match(
                r"^(?P<code_postal>\d{5})\s*(?P<ville>.+)$", ville_partie
            )
            if code_ville_match:
                resultat["code_postal"] = code_ville_match.group("code_postal")
                resultat["ville"] = code_ville_match.group("ville").strip()
            else:
                resultat["ville"] = ville_partie
        else:
            resultat["rue"] = adresse

    for key in resultat:
        if resultat[key]:
            resultat[key] = re.sub(r"\s+", " ", resultat[key]).strip()

    return resultat


def _extract_emplacement_data(cluster) -> Optional[dict]:
    data: dict = {}

    commerce_elem = cluster.select_one(".w-retailer-shop a.enseigne-commerce")
    if commerce_elem:
        # Quand Codata n'a pas de nom d'enseigne précis pour l'emplacement (local vacant,
        # en travaux, ou commerce non identifié individuellement), il affiche l'activité
        # (ou "VIDE") À LA PLACE d'un nom, en marquant le lien avec la classe CSS
        # supplémentaire "enseigne-commerce-activite". Ce n'est pas une vraie enseigne —
        # on exclut ces emplacements plutôt que d'écrire un faux nom dans Airtable.
        classes = commerce_elem.get("class", [])
        if "enseigne-commerce-activite" in classes:
            return None
        data["nom_commerce"] = commerce_elem.get_text(strip=True)

    activite_elem = cluster.select_one(".w-activity span")
    if activite_elem:
        data["activite"] = activite_elem.get("title", "") or activite_elem.get_text(
            strip=True
        )

    adresse_elem = cluster.select_one(".w-address")
    if adresse_elem:
        adresse_complete = adresse_elem.get_text(strip=True)
        data["adresse_complete"] = adresse_complete
        data.update(_separer_adresse(adresse_complete))

    surface_elem = cluster.select_one(".w-surface")
    if surface_elem:
        data["surface"] = surface_elem.get_text(strip=True)

    return data or None


def _extract_results(response: requests.Response, ville: str, rue: str) -> list[dict]:
    soup = BeautifulSoup(response.text, "html.parser")

    result_count_elem = soup.find("h1")
    if result_count_elem and (
        "0 Emplacement" in result_count_elem.get_text()
        or "Aucun résultat" in result_count_elem.get_text()
    ):
        return []

    enseignes: dict[str, dict] = {}
    clusters = soup.select("div.list-cluster")

    for cluster in clusters:
        data = _extract_emplacement_data(cluster)
        if not data:
            continue

        adresse_complete = data.get("adresse_complete", "")
        if re.search(r"\bNiveau\s*-?\d+", adresse_complete, re.IGNORECASE):
            logger.info("Adresse ignorée (contient 'Niveau X'): %s", adresse_complete)
            continue

        nom_commerce = data.get("nom_commerce", "Inconnu")
        adresse_entry = {
            "adresse_complete": data.get("adresse_complete", ""),
            "numero": data.get("numero", ""),
            "rue": data.get("rue", ""),
            "code_postal": data.get("code_postal", ""),
            "ville": data.get("ville", ""),
            "surface": data.get("surface", ""),
        }

        if nom_commerce in enseignes:
            enseignes[nom_commerce]["adresses"].append(adresse_entry)
        else:
            enseignes[nom_commerce] = {
                "nom_commerce": nom_commerce,
                "activite": data.get("activite", ""),
                "ville_recherche": ville,
                "rue_recherche": rue,
                "date_extraction": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "adresses": [adresse_entry],
            }

    results = []
    for enseigne in enseignes.values():
        enseigne["nombre_adresses"] = len(enseigne["adresses"])
        results.append(enseigne)

    return results


def scrape_address(session: requests.Session, ville: str, rue: str) -> list[dict]:
    """Scrape une adresse (ville + rue optionnelle), toutes pages de résultats confondues."""
    response = _submit_search(session, ville, rue)
    if not response:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    results = _extract_results(response, ville, rue)

    sid, detected_last_page = _extract_pagination(soup)
    logger.info(
        "Pagination détectée: sid=%s, dernière page vue dans la nav=%d",
        sid,
        detected_last_page,
    )

    if sid and detected_last_page > 1:
        total_pages = min(detected_last_page, MAX_PAGES)
        if detected_last_page > MAX_PAGES:
            logger.warning(
                "Résultats tronqués: au moins %d pages, limité à %d (%d résultats max).",
                detected_last_page,
                MAX_PAGES,
                MAX_PAGES * PAGE_SIZE,
            )
        logger.info(
            "Récupération de %d page(s) supplémentaire(s) (sid=%s)",
            total_pages - 1,
            sid,
        )

        for page in range(2, total_pages + 1):
            time.sleep(random.uniform(1, 2))
            page_response = _fetch_results_page(session, sid, page)
            if not page_response.ok:
                logger.warning(
                    "Échec récupération page %d/%d pour %s / %s (status=%s)",
                    page,
                    total_pages,
                    ville,
                    rue,
                    page_response.status_code,
                )
                break
            results.extend(_extract_results(page_response, ville, rue))

    return results


def scrape_all(session: requests.Session, addresses: list[dict]) -> dict:
    """
    Scrape une liste d'adresses [{"Ville": ..., "Rue": ...}, ...].
    Retourne {"results": [...], "processed_count": N, "failed": [...]}.
    """
    all_results: list[dict] = []
    failed: list[dict] = []
    processed_count = 0

    for i, address in enumerate(addresses):
        ville = address.get("Ville", "")
        rue = address.get("Rue", "")

        if not ville:
            failed.append({**address, "reason": "Ville manquante"})
            continue

        try:
            results = scrape_address(session, ville, rue)
            processed_count += 1
            for result in results:
                result["ville_originale"] = ville
                result["rue_originale"] = rue
            all_results.extend(results)
            # Petite pause pour rester discret côté Codata (comme dans le script d'origine)
            time.sleep(random.uniform(2, 4))
        except StreetNotRecognizedError as e:
            logger.warning(str(e))
            failed.append({**address, "reason": str(e)})
        except Exception as e:  # noqa: BLE001
            logger.exception("Erreur scraping adresse %s / %s", ville, rue)
            failed.append({**address, "reason": str(e)})

    return {
        "results": all_results,
        "processed_count": processed_count,
        "failed": failed,
    }
