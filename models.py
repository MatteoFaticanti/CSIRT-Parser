from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class Bollettino(BaseModel):
    titolo:             str            = Field(..., min_length=5)
    url:                str
    data_pubblicazione: Optional[str]  = None
    cve_correlate:      List[str]      = Field(default_factory=list)
    cvss:               Optional[float]= Field(None, ge=0.0, le=10.0)
    severity:           str            = "N/D"
    tecnologia:         str            = "Non definita"
    tipologia_attacco:  str            = "Generica / Vulnerabilità non specificata"
    argomenti:          List[str]      = Field(default_factory=list)
    is_exploited:       bool           = False
    has_poc:            bool           = False

    @field_validator('cve_correlate', mode='before')
    def deduplica_cve(cls, v):
        return list(set(v)) if isinstance(v, list) else []