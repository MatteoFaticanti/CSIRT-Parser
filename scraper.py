import asyncio
import json
import logging
import const as c
from functools import wraps
from typing import Optional
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession

from models import Bollettino
import database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_TAGS_STRIP    = c.TAGS_STRIP
_RE_CVE        = c.RE_CVE
_RE_CVSS       = c.RE_CVSS
_RE_ARGOMENTI  = c.RE_ARGOMENTI
_RE_KEV        = c.RE_KEV
_RE_POC        = c.RE_POC
_REGOLE        = c.REGOLE
_TECH_KEYWORDS = c.TECH_KEYWORDS

_RETRY_STATUSES = {429, 500, 502, 503, 504}

def async_retry(retries=3, delay=2):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, retries + 1):
                try:
                    result = await func(*args, **kwargs)
                    if result is None and attempt < retries:
                        logging.warning(f"Tentativo {attempt} fallito (None). Riprovo in {delay * attempt}s...")
                        await asyncio.sleep(delay * attempt)
                        continue
                    return result
                except Exception as e:
                    if attempt == retries:
                        logging.error(f"Fallito dopo {retries} tentativi: {func.__name__} - {e}")
                        return None
                    logging.warning(f"Tentativo {attempt} fallito: {e}. Riprovo in {delay * attempt}s...")
                    await asyncio.sleep(delay * attempt)
        return wrapper
    return decorator


def cvss_to_severity(s: Optional[float]) -> str:
    return "N/D" if s is None else "Critica" if s >= 9 else "Alta" if s >= 7 else "Media" if s >= 4 else "Bassa"


def _rileva_tecnologia(titolo_l: str, tl: str) -> str:
    return next(
        (nome for kw, nome in _TECH_KEYWORDS if kw in titolo_l),
        next((nome for kw, nome in _TECH_KEYWORDS if kw in tl), "Non definita"),
    )


def _raccogli(risultati: list, label: str) -> list[Bollettino]:
    """
    Filtra Bollettino validi.
    """
    out, none_count = [], 0
    for r in risultati:
        if isinstance(r, Bollettino):
            out.append(r)
        elif isinstance(r, Exception):
            logging.error(f"[{label}] task fallito con eccezione: {r}")
        else:
            none_count += 1  # None = fetch fallito o validazione fallita, già loggato in _elabora
    if none_count:
        logging.warning(f"[{label}] {none_count} task terminati senza risultato (fetch/validazione fallita).")
    return out


# Scraper

class CSIRTScraper:
    def __init__(self):
        self.url_rss   = "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192"
        self.url_kev   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._cache:    dict[str, dict] = {}  # CVE → {score, epss, kev}
        self._in_volo:  set[str]        = set() 
        self._kev_cves: set[str]        = set()
        database.init_db()

    # KEV 

    async def carica_kev(self, session: AsyncSession) -> None:
        logging.info("CISA KEV: caricamento in corso...")
        try:
            resp = await session.get(self.url_kev, timeout=15)
            if resp.status_code == 200:
                self._kev_cves = {v["cveID"].upper() for v in resp.json().get("vulnerabilities", [])}
                logging.info(f"CISA KEV: {len(self._kev_cves)} CVE caricati.")
            else:
                logging.warning(f"CISA KEV: risposta {resp.status_code}.")
        except Exception as e:
            logging.error(f"CISA KEV: {e}")

    # Parsing 

    def _analizza(self, titolo: str, testo: str) -> dict:
        tl, titolo_l = f"{titolo} {testo}".lower(), titolo.lower()
        return {
            "cvss":       (float(m.group(1)) if (m := _RE_CVSS.search(testo)) else None),
            "cve":        list({cv.upper() for cv in _RE_CVE.findall(testo)}),
            "tecnologia": _rileva_tecnologia(titolo_l, tl),
            "tipologia":  next((t for t, p in _REGOLE if p.search(tl)), "Generica / Vulnerabilità non specificata"),
            "testo_low":  tl,
        }

    def _argomenti_e_flag(self, soup: BeautifulSoup, tl: str, cve_set: set) -> tuple:
        args = {
            a.get_text(strip=True)
            for nodo in soup.find_all(["strong", "span", "div"], string=_RE_ARGOMENTI)
            if nodo.parent
            for a in nodo.parent.find_all("a")
            if a.get_text(strip=True)
        }
        al = [a.lower() for a in args]
        return (
            list(args),
            bool(self._kev_cves & cve_set)
                or any("exploited" in a or "sfruttato" in a for a in al)
                or "sfruttata attivamente" in tl or "exploited in the wild" in tl
                or bool(_RE_KEV.search(tl)),
            any("poc" in a or "proof of concept" in a for a in al)
                or "proof of concept" in tl or bool(_RE_POC.search(tl)),
        )

    # ── CVSS resolution ───────────────────────────────────────────────────────

    async def _resolve_cvss(self, session: AsyncSession, cves: list[str]) -> float:
        """
        Risolve il CVSS massimo per una lista di CVE interrogando Shodan CVEDB.
        """
        if not cves:
            return 0.0

        da_risolvere = [cv for cv in cves if cv not in self._cache and cv not in self._in_volo]
        self._in_volo.update(da_risolvere)
        try:
            for cve in da_risolvere:
                try:
                    resp = await session.get(f"https://cvedb.shodan.io/cve/{cve}", timeout=10)
                    if resp.status_code == 200:
                        data  = resp.json()
                        score = data.get("cvss_v3") or data.get("cvss") or 0.0
                        self._cache[cve] = {
                            "score": float(score),
                            "epss":  data.get("epss"),
                            "kev":   bool(data.get("kev")),
                        }
                        if self._cache[cve]["kev"]:
                            self._kev_cves.add(cve)
                    elif resp.status_code not in _RETRY_STATUSES:
                        self._cache[cve] = {"score": 0.0, "epss": None, "kev": False}
                except Exception as e:
                    logging.warning(f"CVEDB {cve}: {e}")
                    # Non cachea: errore transitorio, ritentabile
        finally:
            self._in_volo.difference_update(da_risolvere)

        return max((self._cache[cv]["score"] for cv in cves if cv in self._cache), default=0.0)

    # HTTP fetch

    @async_retry(retries=3, delay=2)
    async def _fetch_url(self, session: AsyncSession, url: str) -> Optional[str]:
        resp = await session.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
        logging.warning(f"HTTP {resp.status_code} per {url}")
        return None

    # Pipeline bollettino 

    async def _elabora(self, session: AsyncSession, link: str, titolo: str,
                       data_pub: Optional[str], sem: asyncio.Semaphore) -> Optional[Bollettino]:
        """
        Fetch + parsing completo. Usato sia per nuovi che per aggiornamenti.
          1. fetch  
          2. parsing 
          3. CVSS  
        """
        html = await self._fetch_url(session, link)
        if not html:
            return None

        async with sem:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(_TAGS_STRIP): tag.decompose()
            testo = soup.get_text(separator=" ", strip=True)
            d     = self._analizza(titolo, testo)
            args, exploited, poc = self._argomenti_e_flag(soup, d["testo_low"], set(d["cve"]))

        cvss = max(d["cvss"] or 0.0, await self._resolve_cvss(session, d["cve"])) or None
        try:
            return Bollettino(
                titolo=titolo, url=link, data_pubblicazione=data_pub,
                cve_correlate=d["cve"], cvss=cvss, severity=cvss_to_severity(cvss),
                tecnologia=d["tecnologia"], tipologia_attacco=d["tipologia"],
                argomenti=args, is_exploited=exploited, has_poc=poc,
            )
        except ValueError as e:
            logging.error(f"Validazione fallita su {link}: {e}")
            return None

    # CVSS mancanti

    async def aggiorna_cvss_mancanti(self, session: AsyncSession) -> None:
        """Risolve il CVSS per i bollettini già salvati senza punteggio."""
        privi = database.get_bollettini_senza_cvss()
        if not privi:
            logging.info("Nessun bollettino con CVSS mancante.")
            return

        logging.info(f"Aggiornamento CVSS per {len(privi)} bollettini...")
        aggiornamenti = []
        for bid, cve_json in privi:
            cves  = json.loads(cve_json) if cve_json else []
            score = await self._resolve_cvss(session, cves)
            if score:
                aggiornamenti.append((bid, score, cvss_to_severity(score)))

        database.aggiorna_cvss_batch(aggiornamenti)
        logging.info(f"CVSS aggiornati: {len(aggiornamenti)}/{len(privi)} bollettini.")

    async def run(self):
        sem = asyncio.Semaphore(5)
        async with AsyncSession(impersonate="chrome110") as session:
            rss_xml, _ = await asyncio.gather(
                self._fetch_url(session, self.url_rss),
                self.carica_kev(session),
            )
            if not rss_xml:
                return logging.error("Impossibile scaricare il feed RSS.")

            await self.aggiorna_cvss_mancanti(session)

            date_per_url = database.get_date_per_url()
            items        = BeautifulSoup(rss_xml, "xml").find_all("item")
            logging.info(f"Trovati {len(items)} elementi nel feed.")

            tasks_nuovi:    list = []
            tasks_aggiorna: list = []

            for item in items:
                if not (lt := item.find("link")):
                    continue
                link   = lt.text.strip()
                titolo = t.get_text(strip=True) if (t := item.find("title"))   else "N/A"
                data_p = t.get_text(strip=True) if (t := item.find("pubDate")) else None

                if link not in date_per_url:
                    tasks_nuovi.append(self._elabora(session, link, titolo, data_p, sem))
                elif data_p != date_per_url[link]:
                    logging.info(f"pubDate cambiata → aggiornamento: {link}")
                    tasks_aggiorna.append(self._elabora(session, link, titolo, data_p, sem))
                # else: pubDate identica → skip, zero HTTP

            if tasks_nuovi:
                logging.info(f"Nuovi bollettini da estrarre: {len(tasks_nuovi)}")
                nuovi = _raccogli(await asyncio.gather(*tasks_nuovi, return_exceptions=True), "INSERT")
                logging.info(f"Inseriti: {database.salva_bollettini(nuovi)}")
            else:
                logging.info("Nessun bollettino nuovo.")

            if tasks_aggiorna:
                modificati = _raccogli(await asyncio.gather(*tasks_aggiorna, return_exceptions=True), "UPDATE")
                if modificati:
                    logging.info(f"Aggiornati: {database.aggiorna_bollettini(modificati)}")
                else:
                    logging.info("Nessun bollettino modificato.")

            logging.info("Pipeline completata.")


if __name__ == "__main__":
    asyncio.run(CSIRTScraper().run())