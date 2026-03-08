# Chronos-DFIR Web

> Versión: BETA 1.1 (v168)
> Descripción: Explorador Avanzado de Líneas de Tiempo e Investigaciones Forenses

## Resumen de la Aplicación

Chronos-DFIR Web es una herramienta integral diseñada para analistas forenses y equipos de Respuesta a Incidentes (DFIR). Su objetivo principal es facilitar la ingesta, normalización, enriquecimiento y visualización interactiva de grandes volúmenes de eventos (logs) provenientes de múltiples fuentes. Chronos-DFIR construye una línea de tiempo unificada (Timeline) para la reconstrucción cronológica precisa de incidentes cibernéticos.

**Ubicación del Proyecto:** `/Users/ivanhuerta/Documents/chronos_antigravity`
**Directorio de Pruebas (Artefactos):** `/Users/ivanhuerta/Documents/Artefactos_pruebas`

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
