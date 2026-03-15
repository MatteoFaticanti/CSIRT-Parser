# 🛡️ CSIRT Italia Parser

Un tool automatizzato per raccogliere, arricchire e visualizzare i bollettini di sicurezza pubblicati da **ACN/CSIRT Italia**, con una dashboard interattiva per l'analisi delle vulnerabilità.

---

## Funzionalità

- **Scraping automatico** del feed RSS ufficiale ACN (`acn.gov.it`)
- **Arricchimento CVE** tramite [CVEDB (Shodan)](https://cvedb.shodan.io) — CVSS, EPSS, KEV flag
- **Cross-reference CISA KEV** — rileva automaticamente vulnerabilità attivamente sfruttate
- **Classificazione automatica** della tipologia di attacco (RCE, Ransomware, SQLi, ecc.)
- **Rilevamento tecnologia** tramite dizionario estensibile (100+ vendor/prodotti)
- **Dashboard interattiva** con [Dash](https://dash.plotly.com) + [Dash Mantine Components](https://www.dash-mantine-components.com)
- **Persistenza su SQLite** con aggiornamenti incrementali 

---

## Screenshot

> Dashboard con KPI, grafici e tabella dettaglio bollettini
>
> ![alt text](https://github.com/MatteoFaticanti/CSIRT-Parser/blob/main/img.png?raw=true)

---

## Struttura del progetto

```
├── scraper.py       # Pipeline di scraping e arricchimento
├── app.py           # Dashboard Dash + Mantine
├── database.py      # Gestione SQLite
├── models.py        # Dataclass Bollettino
├── const.py         # Regex, regole di classificazione, dizionario tecnologie
└── requirements.txt
```

---

## Installazione

```bash
git clone https://github.com/MatteoFaticanti/CSIRT-Parser/
cd CSIRT-Parser
pip install -r requirements.txt
```

**requirements.txt**
```
beautifulsoup4
curl_cffi
dash
dash-mantine-components
lxml
pandas
plotly
```

---

## Utilizzo

### 1. Popola il database

```bash
python scraper.py
```

Alla prima esecuzione scarica tutti i bollettini disponibili nel feed RSS (ultimi 50). Le esecuzioni successive scaricano solo i nuovi.

### Avvia la dashboard

```bash
python app.py
```

Webapp su `http://127.0.0.1:8050`.

---

```
## 📊 Dati raccolti per ogni bollettino

| Campo | Descrizione |
|---|---|
| `titolo` | Titolo del bollettino ACN |
| `url` | Link alla pagina originale |
| `data_pubblicazione` | Data di pubblicazione |
| `cve_correlate` | Lista CVE estratti dal testo |
| `cvss` | Punteggio CVSS (da CVEDB o testo) |
| `severity` | Critica / Alta / Media / Bassa / N/D |
| `tecnologia` | Vendor/prodotto rilevato |
| `tipologia_attacco` | Tipo di vulnerabilità classificato |
| `is_exploited` | `True` se in CISA KEV o sfruttato attivamente |
| `has_poc` | `True` se è presente un PoC pubblico |
| `argomenti` | Tag estratti dalla pagina ACN |

```
---
## Fonti dati

| Fonte | Utilizzo |
|---|---|
| [ACN/CSIRT Italia](https://www.acn.gov.it) | Feed RSS bollettini |
| [CVEDB (Shodan)](https://cvedb.shodan.io) | CVSS, EPSS, KEV flag |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilità sfruttate |

---

## Licenza

MIT
