# Sigma Rules Repository — Chronos-DFIR

Repositorio de reglas de detección en formato **Sigma** para Chronos-DFIR, organizado por táctica MITRE ATT&CK y categoría OWASP.

## Estructura

```
rules/
├── sigma/
│   ├── mitre/          ← Reglas por táctica MITRE ATT&CK Enterprise
│   │   ├── ta0001_initial_access/
│   │   ├── ta0002_execution/
│   │   ├── ta0003_persistence/
│   │   ├── ta0005_defense_evasion/
│   │   └── ta0006_credential_access/
│   └── owasp/          ← Reglas para logs WAF / Web Servers
│       ├── A03_injection/
│       ├── A07_auth_failures/
│       └── A10_ssrf/
└── README.md
```

## Uso con Chronos-DFIR

```python
from engine.sigma_compiler import scan_with_sigma_rules
import polars as pl
from pathlib import Path

df = pl.read_csv("upload/events.csv")
df_enriched = scan_with_sigma_rules(df, rules_dir=Path("rules/sigma"))
```

## Referencias
- [SigmaHQ Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- Inspirado en [Chainsaw](https://github.com/WithSecureLabs/chainsaw)
