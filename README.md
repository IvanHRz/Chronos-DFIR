# Chronos-DFIR Web

> Versión: BETA 1.1 (v185)
> Descripción: Explorador Avanzado de Líneas de Tiempo e Investigaciones Forenses

## Resumen de la Aplicación

Chronos-DFIR Web es una herramienta integral diseñada para analistas forenses y equipos de Respuesta a Incidentes (DFIR). Su objetivo principal es facilitar la ingesta, normalización, enriquecimiento y visualización interactiva de grandes volúmenes de eventos (logs) provenientes de múltiples fuentes. Chronos-DFIR construye una línea de tiempo unificada (Timeline) para la reconstrucción cronológica precisa de incidentes cibernéticos.

---

## Funcionalidades Principales e Ingesta Multi-Formato Unificada

La aplicación soporta la carga mediante "Drag & Drop", aceptando una gran variedad de formatos. Todos los archivos ingeridos pasan por un motor de normalización y parseo robusto para unificar su estructura:

### Drag & Drop Artifacts (MFT, EVTX, PLIST) or Reports (CSV, XLSX, TSV, JSON, Parquet, SQLite, TXT)

- **Artefactos Forenses Nativos:**
  - **EVTX (Windows Event Logs):** Procesamiento optimizado de logs de Windows, extrayendo automáticamente atributos clave (EventID, Level, Provider, Computer, descripciones).
  - **MFT (Master File Table):** Parseo y soporte para el análisis profundo de sistemas de archivos NTFS.
  - **PLIST (Property List - macOS):** Detección y parseo automático de archivos PLIST de macOS (como LaunchAgents y LaunchDaemons) usados frecuentemente en mecanismos de persistencia. Extrae rutas, binarios ejecutados y firmas.

- **Formatos Genéricos, de Texto y Reporte:**
  - **TXT (Unified Logs & Texto Plano):** Nuevo motor de parseo regex para extraer logs estructurados (ej. logs unificados de macOS) generados en texto plano, parseando y normalizando información relevante de cada evento en columnas limpias.
  - **CSV / TSV / Excel (.xlsx):** Ingesta de reportes exportados por herramientas como Plaso, Kape, EDRs y automacTC.
  - **JSON / JSONL / NDJSON:** Parseo de eventos estructurados modernos.
  - **Parquet:** Formato columnar de extrema eficiencia para datasets masivos en Big Data alert/hunting.
  - **SQLite (.db):** Lectura directa de bases de datos locales (historial de red, persistencias, telemetría de navegadores).
  - **Streaming Upload:** Manejo de archivos gigantes (+6GB) mediante carga por streaming asíncrono directo al disco para procesar chunks sin saturar la memoria RAM.

### Normalización, Enriquecimiento y Parseo
- **Detección Automática de Columnas:** Estandarización automática universal de `Time`, `EventID`, `Level`, IPs, y usuarios independientemente de la fuente de la que provengan.
- **Reglas Sigma y Yara:** Integración automática de motores de análisis. A medida que el archivo se parsea, cada fila se evalúa con repositorios de reglas Sigma y firmas Yara configuradas, permitiendo etiquetar de inmediato comportamientos maliciosos conocidos en el Grid principal.
- **Análisis de TTPs (MITRE ATT&CK):** Enriquecimiento de la data con tácticas, técnicas y procedimientos (TTPs). Se correlaciona la evidencia en la tabla con la matriz MITRE, permitiendo agrupar detecciones para explicar de un vistazo intenciones operativas del atacante.

---

## Lógica y Flujo de Interfaz (Botones, Grid y Filtros)

Chronos-DFIR utiliza un diseño optimizado (Professional Dark Mode enfocado en el "Data-Ink Ratio", reduciendo distracciones visuales e iluminando alertas operativas críticas).

### 1. Zona de Carga (Drag Drop / Sidebar)
- **Select File:** Invoca el cuadro selectivo del SO. Opera en conjunto directo con la caja de Drop.
- **Process Artifact / Load View:** Lanza los hilos asíncronos en backend (Polars/Regex/Evtx). Inicia parseo, normalización y aplicación de lógica TTP/Reglas.
- **Hard Reset ⟲ (Reset View):** Lógica que purga desde cero de la vista el Dataframe temporal activo, limpia los cachés del UI, los LocalStorages e inyecta un estado en limpio listo para ingerir artefactos ajenos sin riesgo forense de contaminación cruzada.

### 2. Panel de Exportación (Dropdown `Export ▼`)

*Nota Forense: Toda exportación de datos crudos retiene estrictamente el valor normalizado nativo (si es hex, se va en hex), garantizando integridad.*

- **CSV Format / Excel Spreadsheet / JSON Structure:** Exportan siempre y **únicamente** la vista del grid actual. Es decir, respeta todo filtrado activo (Time, Global, Hide Empty, Columns Selected).
- **Context:** Descarga directa de metadatos forenses pule y da contexto (conteo general de IPs únicas, cuentas afectadas, paths sospechosos, hallazgos de TTPs), enlazado con un formato JSON amigable estructurado específicamente para ser consumido eficientemente en un solo prompt a través de LLMs (Inteligencia Artificial) reduciendo consumo de tokens.
- **Zip (Split Artifacts):** Maneja exports masivos (ej. +200MB de grid CSV) que una IA no admitiría en chat directo. Este botón despliega inputs de limitación estricta de peso ("99MB" / "50MB"). Un algoritmo en backend particiona la evidencia en N archivos Zip exactos a la capacidad del botón pulsado.
- **Graphical Report 📄:** Acción combinada backend/frontend. Transforma todo el contexto de análisis general (Histogramas interactivos embebidos en Base64, resúmenes TTP, Sigma tags hallados y resumen de Grid filtrado) a un formato autocontenido portátil en HTML con su propia lógica UI interna para presentarse a niveles Ejecutivos/Administrativos off-line.

### 3. Filtros y Búsqueda del Timeline/Grid

Su lógica de co-dependencia es central. Modificar un vector temporal en el header muta inmediatamente el Grid, y viceversa.

- **Global Search:** Caja de tipeo rápida (debounce). Busca sub-cadenas exactas iterando a través de millones de celdas en memoria de Tabulator (vDOM). **Lógica visual:** Al dar 'enter' recorta las filas no coincidentes y "resalta" el query textual hallado en un fondo amarillo tipo "Highlight".
- **Controles de Tiempo (Start / End + Filter):** La lógica inyecta límites estrictos desde el timestamp nativo más temprano y tardío alojados en memoria del dataset ingerido. Recorta quirúrgicamente los eventos al invocar "Filter".
- **Row Filtering:** Oculta filas de manera manual. Si durante la inspección manual seleccionaste cinco filas atípicas con la check-box (Tag), al pulsar "Row Filtering", Tabulator esconde todo el mar de ruido, dejando a la vista exclusivamente tus selecciones manuales.
- **Hide Empty:** Motor algorítmico clave y un salvavidas del ruido visual. Rastrea iterativamente columna por columna el 100% de la tabla **actual visualizada (con filtros aplicados)**. Si dentro del resultado filtrado detecta que la propición de nulos ("-", vacíos, "nan") es del 100% en dicha columna, la esconde del DOM reduciendo el scrolling horizontal innecesario dramáticamente.
- **Manage Cols:** Motor espacial de organización del framework Grid.
  - **Top:** Localiza las columnas chequeadas en el desplegable y, en un "Reflow" de grid, las expulsa radicalmente hacia el flanco izquierdo (a lado de la hora del evento). Desplaza columnas menos valiosas a la derecha. Función vital para leer cruces de datos (ej. poner "PID", "Process" y "Sigma_Tag" juntas a simple vista).
  - **Filter Cols:** Elimina físicamente cualquier otra columna del Grid que no haya sido solicitada explícitamente y ordena del mismo modo hacia la izquierda.
- **Reset Filters ⟳ / Hide Empty (Toggle):** Reinician los estados locales y devuelven propiedades ocultas al mapa de pantalla.

---

## Lógica y Capacidades del Gráfico (Histograma)

El Gráfico (construido con Chart.js) se redibuja en sincronía con cualquier cambio o limitación efectuada en la barra de búsqueda y filtros; proveyendo retroalimentación visual inmediata.

- **Volumen Interactivo y Detección Algorítmica (Cyber Triage Style):**
  - **Motor de Rango:** Interviene dinámicamente decidiendo el Time-Bucketing. Si ves 7 años juntos, dibuja barras "Mensuales". Si la evidencia subida es del incidente de un día, lo fragmenta automático en "Minutos" o "Segundos".
  - **Categorización Rápida Táctica:** Rojo puro advierte reglas YARA/SIGMA mapeadas en esa hora, o códigos críticos definidos en Syslogs (Alta Prioridad visual). Las columnas de colores frios marcan latido de red o eventos pasivos del O.S. (Baja prioridad).
  - **Media de Tendencia & Pico de Riesgo (Anomalías Computadas):** En lugar de sólo barras normales, el backend inyecta una visualización (línea media punteada dorada). Cuando el motor en Pythón nota 2 a 3 desviaciones estándar por arriba del promedio general (spikes estadistícos masivos), marca ese "Bucket" y alerta verbalmente: "Tendencia: Posible Ataque/Spike".

- **Exportación de Arte:**
  - **📷 PNG:** Captura un dump en canvas HD para pegarse en PowerPoint / Word ejecutivos al instante (Proof of Concept).
  - **� Excel:** Agrupa la base de coordenadas (Eje X Tiempo / Eje Y Conteo) a una tabla cruda descargable en XLSX. Excelente para alimentar herramientas OSINT adicionales o dashboards PowerBI.
  - **Log Scale (Checkbox):** Aplica Log Base 10 (`Math.log10(y)`) reactivo en frontend al instante, permitiendo contrastar un bar-histogram de 1 impacto anómalo a lado de otro de 55,000 conexiones sin que una abrume estáticamente a la otra.

---

## Arquitectura de Tabulator y "Hard-Coded Cols"

Existen lógicamente columnas intocables "Freeze/Pin" que dictaminan el rastreo de eventos para mitigar confusiones:

- **Timestamp:** Formateado al unísono con el Timeline gráfico, rige orden temporal absoluto principal, nunca puede des-mostrarse.
- **No.:** Un id de interfaz (No es id forense). Lógica relacional de conteo directo de render visible. (1 a N logs mostrados activos pos-filtro. Ayuda de guía para saber dónde ibamos leyendo).
- **Tag:** Checkbox de control para alimentar las matrices lógicas como "Row filtering". Nunca oculta.

---

## Arquitectura de Skills y Motor de Detección

Chronos-DFIR cuenta con **76 skills** organizadas en un registro central (`engine/skill_router.py`) que clasifica cada una según su nivel de integración:

| Estado | Cantidad | Descripción |
|--------|----------|-------------|
| **active** | 10 | Código en producción en `engine/` o `app.py` |
| **frontend** | 5 | Implementadas en `static/js/` |
| **rules** | 5 | Implementadas via reglas Sigma YAML o YARA |
| **wired** | 4 | Código `.py` existe pero no está conectado a endpoints |
| **prompt_only** | 52 | System prompts de consulta para agentes IA |

### Motor de Detección
- **Sigma Engine** (`engine/sigma_engine.py`): Compilador dinámico YAML→Polars. Carga reglas de `rules/sigma/` y las evalúa en runtime. Soporta condiciones AND/OR, modificadores `contains`/`startswith`/`endswith`, y correlación temporal.
- **Reglas Sigma**: 86+ reglas cubriendo MITRE ATT&CK (TA0001-TA0011, TA0040) + OWASP Top 10.
- **Reglas YARA**: 7 archivos cubriendo ransomware, LOLBins, C2 frameworks, infostealers, webshells, macOS persistence.
- **Detección offline 100%**: Todas las reglas son archivos locales.

### Módulos del Engine
| Módulo | Líneas | Propósito |
|--------|--------|-----------|
| `engine/forensic.py` | ~1,426 | Análisis forense, sub-analizadores, risk engine |
| `engine/sigma_engine.py` | ~500 | Motor Sigma YAML→Polars |
| `engine/ingestor.py` | ~370 | Ingesta multi-formato (CSV, XLSX, JSON, SQLite, Plist, etc.) |
| `engine/analyzer.py` | ~251 | Histogramas, bucketing temporal, distribuciones |
| `engine/skill_router.py` | ~300 | Registro central de 76 skills con estado de integración |

---

## Flujo de Trabajo Multi-Agente

Chronos se desarrolla con un protocolo de 3 agentes IA:

| Agente | Rol | Herramienta |
|--------|-----|-------------|
| **Claude** | Arquitecto — diseño, implementación, reglas | Claude Code CLI |
| **Gemini CLI** | Ingeniero — QA, profiling, dependencias | Gemini CLI |
| **Antigravity** | Auditor — counter-audits, verificación empírica | Antigravity |

### Documentos de Coordinación (`.agents/`)
- `STATUS.md` — Estado actual (~30 líneas, scores por área)
- `MANDATES.md` — Checklist de pendientes priorizados
- `SCORECARD.md` — Historial de scores por versión
- `DECISION_LOG.md` — Architecture Decision Records (ADRs)
- `RUNBOOK_TEMPLATE.md` — Template para sesiones multi-agente
- `audits/` — Auditorías archivadas por fecha

### CI/CD y Verificación Automática
- **Pre-commit hook**: Verifica app.py < 2000 líneas, 0 pandas, tests passing
- **GitHub Actions** (`.github/workflows/ci.yml`): Tests automatizados, constraints de código, validación Sigma
- **Cachebust automático**: Hash MD5 de assets JS/CSS inyectado via Jinja2 (`{{ v }}`)

---

## Bitácora de Implementaciones Recientes (v162–v168)

### Motor de Riesgo Unificado (Risk Level Homologation)
- **Problema resuelto:** La app mostraba un nivel de riesgo distinto al del reporte HTML porque usaban cálculos distintos (uno incluía `df_iocs`, el otro no).
- **Solución:** Ambos endpoints (`/api/forensic_report` y `/api/export/html`) ahora llaman directamente a `calculate_smart_risk_m4(df_parsed, sigma_hits)` sin pasar `df_iocs`, garantizando resultados idénticos.
- **Archivo clave:** `app.py` → endpoints `forensic_report` y `export_html`.

### Motor Sigma Engine (Detecciones en Tiempo Real)
- **Implementación:** `engine/sigma_engine.py` — carga reglas YAML desde `rules/sigma/` y las evalúa contra el DataFrame cargado usando Polars.
- **Lógica:** Cada regla define `detection.condition` con campos/valores. El motor soporta condiciones AND/OR, modificadores `contains`, `startswith`, `endswith`, `re`.
- **Resultado:** `sigma_hits` — lista de detecciones con `title`, `level`, `mitre_technique`, `matched_rows`.
- **Integración:** Los hits alimentan el cálculo de riesgo (`calculate_smart_risk_m4`), la barra de dashboard, el modal Context y el reporte HTML.

### Reglas YARA — Ransomware
- `rules/yara/ransomware/lockbit.yar` — LockBit 2.x/3.x: strings característicos, extensiones `.lockbit`, nota de rescate, imports PE.
- `rules/yara/ransomware/qilin_agenda.yar` — QILIN/Agenda: ChaCha20/RSA-2048, targets ESXi, rclone exfiltration, Tor C2, Safe Mode bypass.

### Reglas — Cobertura Final (v168)
- **YARA:** 7 archivos → ransomware (LockBit, QILIN, genérico), LOLBins, C2 frameworks (Cobalt Strike/Sliver/Meterpreter), infostealers, webshells, macOS persistence.
- **Sigma:** 32 reglas YAML → cobertura MITRE completa TA0001–TA0011 + TA0040 + OWASP Top 10.
- **Nuevas tácticas añadidas:** TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0007 Discovery, TA0009 Collection, TA0010 Exfiltration, TA0011 C2, TA0040 Impact.
- **Offline 100%:** Todas las reglas son archivos locales. La app no requiere internet para detección.

### EPS (Events Per Second) — Homologación
- **Problema:** `infer_format=True` no existe en Polars 1.x → `.str.to_datetime()` fallaba silenciosamente → EPS = 0.
- **Solución:** Reemplazado por `.str.to_datetime(strict=False)` en todos los endpoints.
- **Columna Timezone:** `get_primary_time_column()` ahora usa `Timezone` como último recurso si no hay otra columna temporal, resolviendo EPS=0 en archivos XDR.

### Exportación JSON
- **Problema:** `df.write_json(pretty=False, row_oriented=True)` → `TypeError` en Polars 1.x.
- **Solución:** Reemplazado por `df.write_ndjson(out_path)` (NDJSON = un JSON por línea, formato estándar para datasets grandes).

### PDF Independiente (Server-Side)
- **Antes:** El PDF era "imprimir HTML desde el navegador" — dependía del HTML abierto y el diálogo de impresión.
- **Ahora:** Endpoint `/api/export/pdf` genera el PDF directamente en el servidor usando **WeasyPrint** y lo descarga como archivo `.pdf` independiente.
- **Instalación:** `weasyprint>=68.0` añadido a `requirements.txt`.

### Modal Forensic Insight Report
- Ampliado a `max-width: 1400px; width: 95%` para aprovechar pantallas grandes.
- `overflow-x: auto` habilitado para scroll horizontal en tablas anchas.
- Sección **Sigma Rule Detections** ahora aparece también en el reporte HTML exportado (no solo en el modal).

### Formatos Soportados Ampliados
- **`.log`** añadido: procesado con el mismo parser de `.txt` (Unified Log, ls-triage, fallback CSV).
- **ZIP:** Solo soporta bundles de `.plist` (LaunchAgents/LaunchDaemons macOS). Especificado en el drag-drop.
- **CSV sin header:** Detección automática de archivos whitespace-delimitados (salida de `ls -la`) — reingesta con `Field_0`, `Field_1`, etc.

### Filtros Anti-Ruido en Dashboard
- Valores sintéticos (`macOS_Unified_Log`, `macOS_Persistence_Info`, `Volatility_RAM_Process`) ya no aparecen en Top Tactic, Top Event IDs ni EventID panels.
- `SYSMON_EVENT_LABELS` promovido a nivel de módulo en `engine/forensic.py` para ser importable desde `app.py`.
- EventIDs numéricos en Top Tactic se muestran como `Win EventID 7036: Service State Change`.

### Top IPs — Corrección
- Columnas genéricas `source`/`destination` removidas del mapeo de IPs en `sub_analyze_context` (causaban que nombres de proveedores como "EVTX" aparecieran como Top IP).

### Risk Level Coloring en HTML Report
- `.risk-Low` (verde `#4ade80`) añadido al CSS del template. Antes el nivel "Low" aparecía sin color.

### Visualizaciones Sin Timestamp
- Cuando no hay columna temporal detectada, el HTML report reemplaza el histograma por mini-charts horizontales de **Top Users**, **Top Processes**, **Top Paths** (Chart.js bar charts).
- Funcionalidad tipo GoAccess/ELK para artefactos forenses sin timestamps.

---

## Bitácora v181 — Fix Definitivo de Exports y Dashboard

### Cache Bust System
- Imports JS usan `?v=185` en `main.js` — SIEMPRE incrementar al cambiar cualquier módulo JS
- `ASSET_VERSION` (MD5 hash) solo bust-ea `main.js` entry point; los módulos internos necesitan version manual

### XLSX Export — Integridad Forense
- `xlsxwriter` con `write_string()` para TODAS las celdas (no solo hex) — previene toda auto-conversión de Excel
- `strings_to_numbers: False` + `num_format: '@'` para columnas hex/hash/GUID
- Polars `infer_schema_length=0` en todas las rutas de lectura CSV — todo como Utf8

### Context Export Completo (CSV + XLSX)
- `_buildForensicSummaryRows()` ahora exporta TODAS las secciones del modal:
  - Header metadata, Timeline Analysis, Sanitized Forensic Summary (IPs, Users, Hosts, Paths, Methods, Violations, Event IDs, Tactics), Chronos Hunter Summary (suspicious patterns, network, logons), Identity & Assets (processes, rare processes, rare paths), Sigma Detections (con sample evidence rows), YARA, MITRE Kill Chain, Cross-Source Correlation, Session Profiles, Risk Justification
- Nuevo endpoint `/api/export/forensic-summary` genera XLSX formateado con xlsxwriter (secciones coloreadas, headers, formato de texto forzado)
- Botón Excel del modal ahora descarga XLSX real (no CSV)

### TTP Summary Strip
- Nuevo elemento `#ttp-summary-strip` debajo del dashboard con badges de severity (CRITICAL: N, HIGH: N) + pills de MITRE techniques (T1003, T1059, etc.)
- Se actualiza dinámicamente con cada refresh del dashboard (filtros, time range)
- Proporciona feedback visual inmediato de que los TTPs cambiaron al filtrar

### Row Selection Persistente
- `_persistentSelectedIds` Set en `grid.js` — sobrevive paginación AJAX
- `getSelectedIds()` retorna del Set persistente
- Backend `_apply_standard_processing` filtra por `_id` con logging (`[SELECTED_IDS]`)

### HTML Report Enhancements
- Sigma evidence tables expandibles (`<details>`) en el reporte HTML
- Print CSS comprehensivo: 30+ reglas para forzar colores legibles en todo contenido dinámico JS
- `<details>` se auto-expanden en print mode

### Skills de Testing
- **`chronos_export_testing`**: 10 tests exhaustivos para CSV, XLSX, JSON, Context CSV, Context XLSX, HTML Report
- **`chronos_filter_diagnostics`**: actualizado con síntomas de TTPs y cache bust

---

## Bitácora v185 — Row Filter Export Fix, Chart Consistency, Hex Protection

### Row Selection Export Fix (Bug Crítico)
- **Problema:** Al clickear "Row Filter", `table.deselectRow()` disparaba el callback `rowDeselected` por cada fila, vaciando `_persistentSelectedIds` y `ChronosState.selectedIds` antes de que export/dashboard pudieran leerlos. Resultado: exports CSV/XLSX ignoraban la selección de filas y exportaban TODO.
- **Solución:** Guard con `_isReloading = true` antes de `deselectRow()` en `applyRowSelectionFilter()`. Restaura `ChronosState.selectedIds` desde `idSet` después. `getSelectedIds()` ahora prioriza `ChronosState.selectedIds` cuando está en selection view.
- **Archivos:** `static/js/grid.js`, `static/js/actions.js`, `static/js/main.js`

### Chart Scale Consistente
- **Problema:** `autoLog` automático (pico/media > 4x) causaba que la misma data se mostrara a veces en log scale y a veces en linear.
- **Solución:** Escala siempre linear por defecto. Log scale solo se activa con el checkbox manual. Barra de interpretación sugiere "💡 considera activar Log Scale" cuando el pico lo amerita.
- **Archivo:** `static/js/charts.js`

### CSV Hex Preservation
- **Problema:** Valores hex (`0x00000030`) en CSV se auto-convertían a decimal al abrir en Excel/Numbers.
- **Solución:** Columnas hex-prone se envuelven en formula `="0x..."` que Excel interpreta como texto. BOM UTF-8 + `quote_style="always"` se mantienen.
- **Archivo:** `app.py`

### PDF/Report Tabla Colores Unificados
- **Problema:** Tablas en el reporte HTML/PDF tenían fondos inconsistentes (gris vs gris-azul).
- **Solución:** Unificación: headers `#f1f5f9`, celdas `#ffffff`, even rows `#f8fafc`. Aplica a `.context-table` y tablas JS-generated (sigma, hunting, context).
- **Archivo:** `templates/static_report.html`

### Debounce SELECTION_CHANGED (Charts)
- **Problema:** Seleccionar múltiples filas disparaba N requests de histogram (uno por fila) saturando el servidor.
- **Solución:** Debounce 400ms en el listener de `SELECTION_CHANGED` en charts.
- **Archivo:** `static/js/charts.js`

### Export Prioriza ChronosState.selectedIds
- `_exportFiltered()` ahora lee primero de `ChronosState.selectedIds` (source of truth) y solo usa `getSelectedIds()` como fallback.
- **Archivo:** `static/js/actions.js`

---

## Bitácora v180.7 — Estabilización Fase 1 Completa

### Sigma Evidence Enrichment (Etapa 1)
- **Sigma Engine** ahora retorna `sample_evidence` (primeras 150 filas con columnas de detección + contexto forense), `matched_columns`, y `all_row_ids` (500 IDs para "View in Grid").
- **YARA** integrado como tarea paralela en el análisis forense (9 tasks en `asyncio.gather`). Resultados incluidos en el modal y en Context Export.
- **Correlation chains** incluyen `row_ids` por entidad correlacionada.
- **Modal forense expandible**: cada detección Sigma es clickeable, muestra tabla de evidencia con columnas forenses relevantes (User, Process, IP, CommandLine, etc.) y botón "View all in Grid" que filtra el grid principal.
- **`FORENSIC_CONTEXT_COLUMNS`**: 27 columnas forenses clave se agregan automáticamente a la evidencia Sigma si existen en los datos (máximo 12 columnas totales por tabla).

### Estabilización de Exports y Filtros (8 bugs corregidos)
1. **Selección persistente de filas**: Las selecciones con checkbox ahora persisten entre páginas AJAX del grid. Los exports CSV/Excel respetan la selección exacta.
2. **Dashboard actualiza con filtros**: TTPs y risk score se recalculan automáticamente al cambiar filtros (global search, tiempo, columnas) con debounce de 1200ms.
3. **Integridad hex en exports**: CSV incluye BOM UTF-8 para que Excel preserve `0x00000030`. XLSX usa `xlsxwriter` con formato texto explícito (`num_format='@'`) en columnas hex/hash/guid.
4. **Charts sin parpadeo**: Animaciones reducidas a 300ms para transiciones suaves al cambiar filtros.
5. **Context modal CSV/Excel**: Ahora exportan un resumen forense estructurado (Sigma hits, YARA, correlación, risk) en vez de datos raw.
6. **PDF legible**: Colores de `.snippet-box`, risk badges y tactic badges corregidos para impresión. Leyenda de colores del histograma (Peak/Above mean/Normal/Average) agregada.
7. **Composición de filtros**: Global search + time filter + column headers + row selection funcionan juntos en exports.

---

## Roadmap de Desarrollo — Fases

| Fase | Nombre | Estado | Descripción |
|------|--------|--------|-------------|
| **Etapa 0** | Estabilización Exports/Filtros | COMPLETADA | 5 bugs de exports, col_filters estandarizado, selected_ids en HTML/PDF, empty columns |
| **Etapa 1** | Enriquecimiento TTP con Contexto | COMPLETADA | Sigma evidence (150 filas + columnas forenses), YARA en forensic_report, correlation row_ids, modal expandible, context export enriquecido |
| **Etapa 1.5** | Estabilización v2 (Testing Real) | COMPLETADA | 8 bugs: hex preservation, persistent selection, dashboard refresh, chart animation, context modal export, PDF print CSS |
| **Etapa 2** | Plataforma de Casos (DuckDB) | PENDIENTE | `engine/case_db.py` + `engine/case_router.py` ya existen. CRUD de casos, fases, archivos, journal. Falta: `pip install duckdb`, tests, verificación |
| **Etapa 3** | Frontend Sidebar + Journal UI | PENDIENTE | Sidebar de navegación de casos, UI de journal/notas, timeline por caso |
| **Etapa 4** | Multi-File + Cross-Correlation | PENDIENTE | Cargar múltiples archivos en un caso, correlación cross-file, timeline unificada multi-fuente |
| **Etapa 5** | MCP Server + AI Chat | PENDIENTE | Model Context Protocol server para integración con LLMs, chat assistant contextual |
| **Etapa 6** | Auto-Narrativa + Export .chronos-case | PENDIENTE | Generación automática de narrativa forense, export de caso completo como bundle portable |

### Principios Arquitectónicos
- Cada etapa es independiente y verificable
- Sin caso abierto = interfaz idéntica a la actual (backward compatible)
- Offline-first: cero dependencias externas en Etapas 0-4
- Cross-platform: Windows/Mac/Linux sin cambios
- `app.py` se mantiene bajo 2000 líneas (routers externos para features nuevas)

### Próximo Paso
Etapa 2 requiere: `pip install duckdb`, verificar CRUD endpoints existentes, tests de integración.
