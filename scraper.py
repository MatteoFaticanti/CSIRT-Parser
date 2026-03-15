import asyncio
import logging
import const as c
from functools import wraps
from typing import Optional
from bs4 import BeautifulSoup
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

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


def async_retry(retries=3, delay=2):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, retries + 1):
                try:
                    return await func(*args, **kwargs)
                except (RequestsError, Exception) as e:
                    if attempt == retries:
                        logging.error(f"Fallito dopo {retries} tentativi: {func.__name__} - {e}")
                        return None
                    logging.warning(f"Tentativo {attempt} fallito. Riprovo in {delay * attempt}s...")
                    await asyncio.sleep(delay * attempt)
        return wrapper
    return decorator


def cvss_to_severity(s: Optional[float]) -> str:
    return "N/D" if s is None else "Critica" if s >= 9 else "Alta" if s >= 7 else "Media" if s >= 4 else "Bassa"


def _rileva_tecnologia(titolo_l: str, tl: str) -> str:
    return next(
        (nome for kw, nome in _TECH_KEYWORDS if kw in titolo_l),
        next((nome for kw, nome in _TECH_KEYWORDS if kw in tl), "Non definita")
    )


class CSIRTScraper:
    def __init__(self):
        self.url_rss  = "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192"
        self.url_kev  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        # Cache: { "CVE-XXXX-YYYY": {"score": 9.8, "epss": 0.97, "kev": True} }
        self._cache:    dict[str, dict] = {}
        self._kev_cves: set[str]        = set()
        database.init_db()

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

    async def _cvedb_batch(self, session: AsyncSession, cves: list[str]) -> dict[str, dict]:
        """CVEDB (Shodan): Ritorna score + EPSS + KEV."""
        risultati: dict[str, dict] = {}

        async def fetch_one(cve: str) -> None:
            try:
                resp = await session.get(f"https://cvedb.shodan.io/cve/{cve}", timeout=10)
                if resp.status_code == 200:
                    data  = resp.json()
                    score = data.get("cvss_v3") or data.get("cvss") or 0.0
                    if score:
                        risultati[cve] = {
                            "score": float(score),
                            "epss":  data.get("epss"),
                            "kev":   bool(data.get("kev")),
                        }
            except Exception as e:
                logging.warning(f"CVEDB: {cve}: {e}")

        await asyncio.gather(*[fetch_one(cve) for cve in cves])
        if risultati:
            logging.info(f"CVEDB: {len(risultati)}/{len(cves)} CVE trovati.")
        return risultati

    async def _resolve_cvss(self, session: AsyncSession, cves: list[str]) -> float:
        """Risolve il CVSS massimo per una lista di CVE tramite CVEDB."""
        if not cves:
            return 0.0
        da_risolvere = [cv for cv in cves if cv not in self._cache]
        if da_risolvere:
            for cve, data in (await self._cvedb_batch(session, da_risolvere)).items():
                self._cache[cve] = data
                if data.get("kev"):
                    self._kev_cves.add(cve)
        return max((self._cache.get(cv, {}).get("score", 0.0) for cv in cves), default=0.0)

    @async_retry(retries=3, delay=2)
    async def _fetch_url(self, session: AsyncSession, url: str) -> Optional[str]:
        resp = await session.get(url)
        return resp.text if resp.status_code == 200 else None

    async def _elabora(self, session: AsyncSession, link: str, titolo: str,
                       data_pub: Optional[str], sem: asyncio.Semaphore) -> Optional[Bollettino]:
        async with sem:
            if not (html := await self._fetch_url(session, link)):
                return None
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(_TAGS_STRIP): tag.decompose()
            d    = self._analizza(titolo, soup.get_text(separator=" ", strip=True))
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
                logging.error(f"Validazione fallita su {link}: {e}"); return None

    async def run(self):
        url_noti, sem = set(database.get_url_noti()), asyncio.Semaphore(5)
        async with AsyncSession(impersonate="chrome110") as session:
            rss_xml, _ = await asyncio.gather(
                self._fetch_url(session, self.url_rss),
                self.carica_kev(session),
            )
            if not rss_xml:
                return logging.error("Impossibile scaricare il feed RSS.")

            items, tasks = BeautifulSoup(rss_xml, "xml").find_all("item"), []
            logging.info(f"Trovati {len(items)} elementi nel feed.")
            for item in items:
                if not (lt := item.find("link")): continue
                if (link := lt.text.strip()) in url_noti:
                    logging.info("Raggiunto bollettino noto. DB sincronizzato."); break
                tasks.append(self._elabora(
                    session, link,
                    t.get_text(strip=True) if (t := item.find("title")) else "N/A",
                    t.get_text(strip=True) if (t := item.find("pubDate")) else None,
                    sem,
                ))

            if not tasks:
                return logging.info("Nessun alert nuovo trovato.")
            logging.info(f"Avvio estrazione per {len(tasks)} bollettini...")
            inseriti = database.salva_bollettini(
                [r for r in await asyncio.gather(*tasks, return_exceptions=True) if isinstance(r, Bollettino)]
            )
            logging.info(f"Pipeline completata: {inseriti} bollettini salvati.")


if __name__ == "__main__":
    asyncio.run(CSIRTScraper().run())