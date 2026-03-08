import polars as pl
from datetime import datetime
from typing import Optional, List, Any
import json
import functools
import operator
import logging

# Set up logging for the engine
logger = logging.getLogger("chronos.engine")

# Forensic Hierarchies for Time and Event Identification
TIME_HIERARCHY = [
    "EventTime", "ProcessLaunchTime", "FirstSeen", 
    "LogReceivedTime", "LastSeen", "timestamp", 
    "time", "date", "datetime", "utc"
]

EVENT_ID_HIERARCHY = [
    "WinEventId", "EventId", "EventID", 
    "Id", "ID", "EventName"
]

def parse_time_boundary(t_str: Optional[str]) -> Optional[datetime]:
    """Robustly parse start/end times from frontend strings."""
    if not t_str or t_str == "null":
        return None
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
        try:
            return datetime.strptime(t_str, fmt)
        except:
            continue
    try:
        # Handle ISO with Z or offsets
        return datetime.fromisoformat(t_str.replace('Z', '+00:00'))
    except:
        return None

def get_primary_time_column(columns: List[str]) -> Optional[str]:
    """
    Standardized logic to pick the best time column for filtering and analysis.
    Uses the global TIME_HIERARCHY priority list.
    """
    # 1. Try exact matches from hierarchy
    for h_col in TIME_HIERARCHY:
        for col in columns:
            if col.lower() == h_col.lower():
                return col
                
    # 2. Fallback: Generic keywords (prefer non-timezone first, then allow timezone as last resort)
    candidates = ['time', 'timestamp', 'date', 'datetime', 'seen', 'created']
    timezone_fallback = None
    for col in columns:
        lower_col = col.lower()
        if 'timezone' in lower_col:
            timezone_fallback = col  # save as last resort
            continue
        if any(c in lower_col for c in candidates):
            return col
    if timezone_fallback:
        return timezone_fallback
            
    return None

def sanitize_context_data(lf: pl.LazyFrame) -> pl.LazyFrame:
    """
    Applies strict forensic sanitization to forensic telemetry.
    Ensures EventIDs are valid integers and cleans common artifacts.
    """
    try:
        schema = lf.collect_schema()
        cols = schema.names()
        
        # 1. Find the best Event ID source using global hierarchy
        eid_col = None
        for h_col in EVENT_ID_HIERARCHY:
            if h_col in cols:
                eid_col = h_col
                break
        
        # 2. Apply Sanitization Expressions
        exprs = []
        
        # --- Event ID Validation ---
        if eid_col:
            # Cast to string, strip .0, cast to int, and filter range
            exprs.append(
                pl.col(eid_col).cast(pl.Utf8)
                .str.replace(r"\.0$", "", literal=False)
                .cast(pl.Int64, strict=False)
                # Using map_elements for compatibility with newer Polars if necessary, 
                # but staying with the functional equivalent of the original .apply()
                .map_elements(lambda x: x if x is not None and 0 < x < 65535 else None, return_dtype=pl.Int64)
                .alias("Validated_EventID")
            )
        
        if exprs:
            return lf.with_columns(exprs)
        return lf
    except Exception as e:
        logger.error(f"Sanitization error: {e}")
        return lf

def normalize_time_columns_in_df(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Normalizes all columns that look like timestamps to a standard string format."""
    try:
        schema = lf.collect_schema()
        time_keywords = ['time', 'date', 'timestamp', 'lastseen', 'created', 'seen', 'firstseen']

        for col_name, dtype in schema.items():
            if any(k in col_name.lower() for k in time_keywords):
                c = pl.col(col_name)

                try:
                    # 1. Datetime / Date
                    if dtype in [pl.Datetime, pl.Date]:
                        lf = lf.with_columns(c.dt.strftime("%Y-%m-%d %H:%M:%S").alias(col_name))

                    # 2. Numeric Epoch (Int/Float)
                    elif dtype in [pl.Int64, pl.Float64, pl.UInt64, pl.Int32, pl.Float32, pl.UInt32]:
                        lf = lf.with_columns(
                            pl.when(c < 30000000000).then(pl.from_epoch(c.cast(pl.Int64) * 1000, time_unit="ms"))
                            .otherwise(pl.from_epoch(c.cast(pl.Int64), time_unit="ms"))
                            .dt.strftime("%Y-%m-%d %H:%M:%S")
                            .alias(col_name)
                        )

                    # 3. String (Most common)
                    elif dtype in [pl.String, pl.Utf8]:
                        # Cleaning: Remove timezone offsets for simpler parsing
                        c_clean = c.str.replace(r"[\+\-]\d{2}:\d{2}$", "", literal=False).str.replace("Z$", "", literal=False)
                        
                        # Prepare for Epoch in String check
                        is_hex = c.str.contains(r"^0x[0-9a-fA-F]+$", literal=False)
                        c_float = pl.when(is_hex).then(None).otherwise(c.cast(pl.Float64, strict=False))
                        c_int = c_float.cast(pl.Int64)

                        parsed_date = pl.coalesce([
                             # Smart Epoch Logic for Strings (only if not hex)
                            pl.when(c_int.is_not_null() & (c_int < 30000000000)).then(pl.from_epoch(c_int.fill_null(0) * 1000, time_unit="ms"))
                              .when(c_int.is_not_null()).then(pl.from_epoch(c_int.fill_null(0), time_unit="ms")),

                            # Strict string parsing with various formats
                            c_clean.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                            c_clean.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                            c_clean.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                            c_clean.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                            c_clean.str.to_datetime("%Y/%m/%d %H:%M:%S", strict=False),
                            c_clean.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                        ])
                        
                        lf = lf.with_columns(parsed_date.dt.strftime("%Y-%m-%d %H:%M:%S").alias(col_name))

                except Exception as e:
                    logger.warning(f"Failed to normalize column {col_name}: {e}")
                    continue

        return lf
    except Exception as e:
        logger.error(f"Time normalization error: {e}")
        return lf


def sub_analyze_timeline(df: pl.DataFrame) -> dict:
    """Timeline Analysis Sub-task — uses adaptive bucketing consistent with main chart"""
    stats = {"type": "timeline", "peaks": [], "time_range": "N/A"}

    # Resolve primary time column
    time_col = get_primary_time_column(df.columns)

    if time_col:
        try:
            ts_col = df[time_col].drop_nulls()
            if ts_col.is_empty():
                return stats

            ts_min = ts_col.min()
            ts_max = ts_col.max()

            # Adaptive bucketing — same logic as analyze_dataframe
            try:
                duration = (ts_max - ts_min).total_seconds()
            except Exception:
                duration = 0

            if duration <= 0:
                bucket = "1h"
            elif duration < 3 * 3600:
                bucket = "5m"
            elif duration < 6 * 3600:
                bucket = "15m"
            elif duration < 12 * 3600:
                bucket = "30m"
            elif duration < 48 * 3600:
                bucket = "1h"
            elif duration < 7 * 86400:
                bucket = "6h"
            else:
                bucket = "1d"

            bucketed = (
                df.with_columns(pl.col(time_col).dt.truncate(bucket).alias("_tb"))
                .group_by("_tb")
                .agg(pl.len().alias("count"))
                .sort("count", descending=True)
                .head(3)
            )
            if not bucketed.is_empty():
                stats["peaks"] = [
                    {"hour": row["_tb"].strftime("%Y-%m-%d %H:%M"), "count": row["count"]}
                    for row in bucketed.iter_rows(named=True)
                ]

            # Time range string
            stats["time_range"] = f"{ts_min} to {ts_max}"
        except Exception:
            pass
    return stats

SYSMON_EVENT_LABELS = {
    "1": "Process Create", "2": "File Creation Time Changed",
    "3": "Network Connection", "4": "Sysmon State Change",
    "5": "Process Terminated", "6": "Driver Loaded",
    "7": "Image Loaded / Svc Ctrl Mgr", "8": "Create Remote Thread",
    "9": "Raw Access Read", "10": "Process Access",
    "11": "File Create", "12": "Registry CreateKey/Delete",
    "13": "Registry SetValue", "14": "Registry Rename",
    "15": "FileStream Create", "16": "Sysmon Config Change",
    "17": "Pipe Created", "18": "Pipe Connected",
    "19": "WMI Filter", "20": "WMI Consumer",
    "21": "WMI Binding", "22": "DNS Query",
    "23": "File Delete (Archived)", "24": "Clipboard Changed",
    "25": "Process Tampering", "26": "File Delete (Logged)",
    "27": "File Block Executable", "28": "File Block Shredding",
    "29": "File Executable Detected",
    "41": "System Unexpected Shutdown", "104": "System Log Cleared / Task Triggered",
    "1102": "Security Log Cleared",
    "4624": "Logon Success", "4625": "Logon Failure",
    "4627": "Group Membership Info", "4634": "Logoff",
    "4647": "User Initiated Logoff", "4648": "Logon with Explicit Creds",
    "4656": "Handle Requested", "4657": "Registry Value Modified",
    "4660": "Object Deleted", "4661": "Handle Requested (SAM)",
    "4662": "Object Operation", "4663": "Object Access",
    "4670": "Object Permissions Changed", "4672": "Special Logon",
    "4673": "Privileged Service Called", "4674": "Privileged Object Operation",
    "4688": "Process Create (Windows)", "4689": "Process Terminated",
    "4697": "Service Installed", "4698": "Scheduled Task Created",
    "4699": "Scheduled Task Deleted", "4700": "Scheduled Task Enabled",
    "4701": "Scheduled Task Disabled", "4702": "Scheduled Task Updated",
    "4703": "Token Right Adjusted", "4704": "User Right Assigned",
    "4705": "User Right Removed", "4706": "New Trust to Domain",
    "4716": "Trusted Domain Info Modified", "4718": "System Security Access Removed",
    "4719": "Audit Policy Changed", "4720": "User Account Created",
    "4722": "User Account Enabled", "4723": "Password Change Attempt",
    "4724": "Password Reset Attempt", "4725": "User Account Disabled",
    "4726": "User Account Deleted", "4728": "Member Added to Global Group",
    "4729": "Member Removed from Global Group", "4732": "Member Added to Local Group",
    "4733": "Member Removed from Local Group", "4738": "User Account Changed",
    "4740": "User Account Locked Out", "4756": "Member Added to Universal Group",
    "4768": "Kerberos TGT Requested", "4769": "Kerberos Service Ticket",
    "4770": "Kerberos Ticket Renewed", "4771": "Kerberos Pre-Auth Failed",
    "4776": "NTLM Auth", "4778": "Session Reconnected",
    "4779": "Session Disconnected", "4781": "Account Name Changed",
    "4798": "User Local Group Enumerated", "4799": "Group Membership Enumerated",
    "4946": "Firewall Rule Added", "4947": "Firewall Rule Modified",
    "4948": "Firewall Rule Deleted",
    "5140": "Network Share Accessed", "5142": "Network Share Created",
    "5145": "Network Share Access Check",
    "5156": "Network Connection Allowed", "5157": "Network Connection Blocked",
    "7034": "Service Crashed", "7035": "Service Control Request",
    "7036": "Service State Change", "7040": "Service Start Type Changed",
    "7045": "New Service Installed",
    "4103": "PS Module Logging", "4104": "PS Script Block Logging",
    "4105": "PS Script Start", "4106": "PS Script Stop",
    "14553": "WinRM Session Created", "14554": "WinRM Session Closed",
    "5805": "Computer Account Auth Failed", "5723": "Computer Auth Failed",
    "7031": "Service Terminated Unexpectedly",
}


def sub_analyze_context(df: pl.DataFrame) -> dict:
    """Context and Sanitization Sub-task — WAF-aware with Threat Profiling."""
    stats = {"type": "context", "event_ids": [], "tactics": [], "threat_actors": [],
             "metadata": {"system": "Chronos-DFIR", "action_required": ""}}
    lf_sanitized = sanitize_context_data(df.lazy())
    df_s = lf_sanitized.collect()

    # --- WAF Detection: try to generate Threat Profiles ---
    waf_cols = {"ViolationCategory", "ClientIP", "SrcIP", "X-Forwarded-For",
                "RequestPath", "WAF_Rule", "AttackType", "Triggered_Rule",
                "forensic_category"}
    if waf_cols & set(df.columns):
        try:
            profiles = generate_waf_threat_profiles(df)
            stats["threat_actors"] = profiles
            stats["metadata"]["action_required"] = (
                "Analyze these Top 10 threat actors. Correlate top_rules with "
                "payload_samples to determine if attacks are targeted (SQLi/XSS) "
                "or automated scanners. Note dwell time and first/last_seen for "
                "timeline reconstruction."
            )
            stats["metadata"]["total_attackers_profiled"] = len(profiles)
        except Exception as _we:
            logger.warning(f"WAF profiling in context failed: {_we}")
    
    # Event ID column — expanded to cover XDR/EDR formats
    event_col = next((
        c for c in df_s.columns if c.lower() in [
            "wineventid", "eventid", "event_id", "eventsubid", "validated_eventid",
            "id", "ruleid", "rule_id", "signatureid", "signature_id"
        ]
    ), None)
    # Prefer Validated_EventID (integers only) if available — avoids synthetic labels like "macOS_Unified_Log"
    if "Validated_EventID" in df_s.columns:
        event_col = "Validated_EventID"
    if event_col:
        # Known synthetic file-type constants that should never appear as Event IDs
        _synthetic_ids = {
            "macos_unified_log", "macos_persistence_info", "macos_bulk_plist",
            "volatility_ram_process", "macos_plist_item", "unknown", "n/a", "-", ""
        }
        try:
            df_s = df_s.with_columns(
                pl.col(event_col).cast(pl.Utf8, strict=False)
                  .str.replace(r"\.0$", "").alias("_clean_event_id")
            )
            eid_counts = (
                df_s.filter(
                    pl.col("_clean_event_id").is_not_null() &
                    (~pl.col("_clean_event_id").cast(pl.Utf8)
                       .str.to_lowercase().is_in(list(_synthetic_ids)))
                )
                .group_by("_clean_event_id")
                .agg(pl.len().alias("count"))
                .sort("count", descending=True)
                .head(10)
            )
            if not eid_counts.is_empty():
                stats["event_ids"] = [
                    {
                        "id": str(row["_clean_event_id"]),
                        "label": SYSMON_EVENT_LABELS.get(
                            str(row["_clean_event_id"]), "Event"
                        ),
                        "count": row["count"]
                    }
                    for row in eid_counts.iter_rows(named=True)
                ]
        except Exception as e:
            logger.warning(f"Error extracting event IDs: {e}")

    # Tactic/Category column — expanded for XDR/EDR (EventName, EventSubName, ThreatType)
    tactic_col = next((
        c for c in df_s.columns if c.lower() in [
            "forensic_category", "tactic", "category", "taskcategory",
            "provider", "owaspcategory", "violationcategory",
            "eventsubname", "eventname", "threatthreat", "threattype",
            "detectionname", "detectiontype", "actresult", "act"
        ]
    ), None)
    if tactic_col:
        try:
            cat_counts = (
                df_s.filter(
                    pl.col(tactic_col).is_not_null() &
                    (pl.col(tactic_col).cast(pl.Utf8).str.len_chars() > 1)
                )
                .group_by(tactic_col)
                .agg(pl.len().alias("count"))
                .sort("count", descending=True)
                .head(10)
            )
            if not cat_counts.is_empty():
                stats["tactics"] = [{"category": str(row[tactic_col]), "count": row["count"]} for row in cat_counts.iter_rows(named=True)]
        except Exception as e:
            logger.warning(f"Error extracting tactics: {e}")

    # ========================================================================
    # Field extraction — now covers XDR/EDR column naming conventions
    # IP: also handles Dst/Src which may contain list-strings like ['ip1','ip2']
    # ========================================================================
    for field_name, search_keys, fallback_keys, exclude_keys, result_key in [
        # IPs — covers WAF, EVTX, XDR (Dst/Src), cloud, UDM
        ("IP", [
            "endpointip", "senderip", "objectips", "dst", "src",
            "ip", "destinationip", "sourceip", "clientip", "c-ip",
            "remoteaddress", "externalip",
            "eventdataipaddress", "udm.principal.ip", "udm.target.ip",
            "udm.principal.asset.ip", "udm.target.asset.ip"
        ], ["ip", "addr"], ["mac", "zip", "desc", "build", "version", "principal", "script", "source", "dest", "entity", "provider", "channel"], "ips"),

        # Users — covers XDR ProcessUser, EVTX TargetUserName, macOS triage Owner
        ("User", [
            "processuser", "user", "username", "account", "subject",
            "accountname", "eventdatatargetusername", "eventdatasubjectusername",
            "logonuser", "objectuser", "owner",
            "udm.principal.user.userid", "udm.target.user.userid"
        ], ["user", "account"], ["agent", "browser", "sid"], "users"),

        # Hosts — covers XDR HostName/EndpointHostName, UDM Hostname
        ("Host", [
            "hostname", "endpointhostname", "computer", "computername",
            "host", "dvchost", "s-computername", "system", "udm.principal.hostname",
            "udm.target.hostname", "udm.principal.asset.hostname"
        ], ["host", "computer"], ["target", "dest", "intermediary"], "hosts"),

        # Processes — covers XDR ProcessName, EVTX Image
        ("Process", [
            "processname", "image", "processfilepath", "process",
            "parentname", "pname", "udm.principal.process.file.full_path", "udm.target.process.file.full_path"
        ], ["process", "image"], ["parent", "object", "src"], "processes"),

        # Commands — covers XDR ProcessCmd, EVTX CommandLine
        ("Command", [
            "processcmd", "commandline", "parentcmd", "objectcmd",
            "udm.principal.process.command_line", "udm.target.process.command_line"
        ], ["cmd", "command", "cmdline"], ["hash", "id", "time"], "commands"),

        # Paths — URI or file paths, Chronos unified Destination_Entity
        ("Path", [
            "destination_entity", "uri", "path", "cs-uri-stem", "url", "request_uri", "requesturl",
            "filepath", "fullpath", "objectfilepath", "udm.network.http.url"
        ], ["uri", "path", "destination"], ["device", "hash", "security"], "paths"),

        # Event category / violation
        ("Violation", [
            "violationcategory", "violation_category", "rule_message",
            "eventsubname", "detectionname", "threatthreat", "udm.security_result.category_details",
            "udm.security_result.summary", "udm.security_result.rule_name", "action"
        ], ["violation", "detection", "threat", "action", "category"], ["id", "time", "details"], "violations")
    ]:
        col = next((c for c in df_s.columns if c.lower() in search_keys), None)
        if not col:
            col = next((
                c for c in df_s.columns
                if any(k in c.lower() for k in fallback_keys)
                and not any(e in c.lower() for e in exclude_keys)
            ), None)

        if col:
            try:
                # For destination_entity used as paths: validate values look like file/URI paths
                # (start with '/' or contain '.plist'/'.txt'/known path patterns)
                # to avoid log message fragments being classified as paths.
                if result_key == "paths" and col.lower() == "destination_entity":
                    sample = df_s[col].cast(pl.Utf8).drop_nulls().head(30).to_list()
                    path_like = sum(
                        1 for v in sample
                        if str(v).startswith("/") or str(v).startswith("\\")
                        or any(ext in str(v).lower() for ext in [".plist", ".sh", ".py", ".rb", ".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"])
                    )
                    if path_like < max(1, len(sample) * 0.3):
                        col = None  # Not path-like enough, skip
                if not col:
                    stats[result_key] = []
                    continue

                # For Dst/Src columns that may contain Python list strings,
                # extract first item robustly by stripping brackets and splitting
                col_ser = df_s[col].cast(pl.Utf8)
                is_list_col = col_ser.drop_nulls().head(10).to_list()
                looks_like_list = any(
                    str(v).strip().startswith("[") for v in is_list_col if v
                )
                if looks_like_list:
                    df_s = df_s.with_columns(
                        pl.col(col).cast(pl.Utf8)
                          .str.replace_all(r"[\[\]'\"]", "", literal=False)
                          .str.split(",")
                          .list.first()
                          .str.strip_chars()
                          .alias("_extracted_" + col)
                    )
                    work_col = "_extracted_" + col
                else:
                    work_col = col

                path_filter = (
                    pl.col(work_col).cast(pl.Utf8).str.starts_with("/") |
                    pl.col(work_col).cast(pl.Utf8).str.starts_with("\\") |
                    pl.col(work_col).cast(pl.Utf8).str.contains(r"\.(plist|sh|py|exe|dll|ps1|bat|vbs|js|txt|log)$", literal=False)
                ) if result_key == "paths" else pl.lit(True)

                counts = (
                    df_s.filter(
                        pl.col(work_col).is_not_null() &
                        (pl.col(work_col).cast(pl.Utf8).str.len_chars() > 0) &
                        (~pl.col(work_col).cast(pl.Utf8).str.to_lowercase().is_in(
                            ["unknown", "na", "n/a", "-", "null", "none", "", "[]"]
                        )) &
                        path_filter
                    )
                    .group_by(work_col)
                    .agg(pl.len().alias("count"))
                    .sort("count", descending=True)
                    .head(8)
                )
                if not counts.is_empty():
                    stats[result_key] = [
                        {"id": str(row[work_col]), "count": row["count"]}
                        for row in counts.iter_rows(named=True)
                    ]
            except Exception as e:
                logger.warning(f"Error extracting top {field_name}: {e}")

    return stats


# =============================================================================
# SKILL 49: El Decodificador WAF + SKILL 50: El Agrupador de Sesiones
# =============================================================================
def generate_waf_threat_profiles(df: pl.DataFrame) -> list:
    """
    Normalizes raw WAF CSV columns (vendor-agnostic via pl.coalesce) then
    profiles each attacking IP into an actionable intelligence card.
    Returns Top 10 attacker dicts ready for JSON/HTML Threat Cards.
    """
    if df.is_empty():
        return []

    cols = df.columns

    def _coalesce_col(candidates: list, alias: str) -> pl.Expr:
        found = [c for c in candidates if c in cols]
        if not found:
            return pl.lit(None).cast(pl.Utf8).alias(alias)
        if len(found) == 1:
            return pl.col(found[0]).cast(pl.Utf8).alias(alias)
        return pl.coalesce([pl.col(c).cast(pl.Utf8) for c in found]).alias(alias)

    try:
        lf = df.lazy().with_columns([
            _coalesce_col(["ClientIP", "SrcIP", "SourceIP", "X-Forwarded-For",
                           "c-ip", "RemoteAddress", "AttackerIP", "IPAddress"], "Attacker_IP"),
            _coalesce_col(["RequestPath", "URI", "URL", "cs-uri-stem", "RequestURI",
                           "TargetURI", "Path", "uri"], "Target_URI"),
            _coalesce_col(["RuleName", "AttackType", "AlertName", "WAF_Rule",
                           "ViolationCategory", "Violation_Category", "EventName",
                           "forensic_category", "Severity"], "Triggered_Rule"),
            _coalesce_col(["Payload", "QueryString", "cs-uri-query", "RequestBody",
                           "UserAgent", "cs-user-agent"], "Attack_Payload"),
            _coalesce_col(["Timestamp", "Time", "EventTime", "date", "time",
                           "datetime", "LogReceivedTime"], "Event_Time"),
        ])

        lf_valid = lf.filter(
            pl.col("Attacker_IP").is_not_null() &
            (pl.col("Attacker_IP") != "UNKNOWN") &
            (pl.col("Attacker_IP").str.len_chars() > 3)
        )

        agg_df = (
            lf_valid.group_by("Attacker_IP").agg([
                pl.len().alias("Total_Requests"),
                pl.col("Target_URI").drop_nulls().value_counts(sort=True).head(3).alias("Top_URIs_raw"),
                pl.col("Triggered_Rule").drop_nulls().value_counts(sort=True).head(3).alias("Top_Rules_raw"),
                pl.col("Attack_Payload").drop_nulls().unique().head(3).alias("Payload_Samples"),
                pl.col("Event_Time").min().alias("First_Seen"),
                pl.col("Event_Time").max().alias("Last_Seen"),
            ])
            .sort("Total_Requests", descending=True)
            .head(10)
            .collect()
        )
    except Exception as e:
        logger.warning(f"WAF Threat Profiler failed: {e}")
        return []

    try:
        from urllib.parse import unquote
    except ImportError:
        def unquote(s): return s  # type: ignore

    def _clean_vc(raw_list) -> dict:
        result = {}
        if not isinstance(raw_list, list):
            return result
        for item in raw_list:
            if isinstance(item, dict):
                vals = list(item.values())
                if len(vals) >= 2:
                    result[str(vals[0])] = int(vals[1])
        return result

    profiles = []
    for row in agg_df.iter_rows(named=True):
        first_seen = str(row.get("First_Seen") or "N/A")
        last_seen  = str(row.get("Last_Seen") or "N/A")
        try:
            from datetime import datetime as _dt
            t0 = _dt.fromisoformat(first_seen.split(".")[0])
            t1 = _dt.fromisoformat(last_seen.split(".")[0])
            sec = int((t1 - t0).total_seconds())
            dwell_str = f"{sec}s" if sec < 60 else f"{sec // 60}m {sec % 60}s"
        except Exception:
            dwell_str = "N/A"

        raw_payloads = row.get("Payload_Samples") or []
        clean_payloads = []
        for p in (raw_payloads if isinstance(raw_payloads, list) else []):
            if p and str(p).strip():
                clean_payloads.append(unquote(str(p))[:200])

        # Try to assign MITRE ID from rule name
        rule_top = list(_clean_vc(row.get("Top_Rules_raw") or {}).keys())
        rule_str = " ".join(rule_top).lower()
        mitre_id = "T1190" if any(k in rule_str for k in ["sqli","xss","lfi","rce","inject"]) \
                else "T1110" if any(k in rule_str for k in ["login","brute","auth","cred"]) \
                else "T1595" if any(k in rule_str for k in ["scan","probe","recon"]) \
                else "T1498" if any(k in rule_str for k in ["dos","flood","ddos"]) \
                else "T1602" if any(k in rule_str for k in ["ssrf","metadata"]) \
                else "—"

        profiles.append({
            "ip":             row["Attacker_IP"],
            "total":          row["Total_Requests"],
            "first_seen":     first_seen,
            "last_seen":      last_seen,
            "dwell":          dwell_str,
            "top_uris":       _clean_vc(row.get("Top_URIs_raw") or []),
            "top_rules":      _clean_vc(row.get("Top_Rules_raw") or []),
            "payload_samples": clean_payloads,
            "mitre_id":       mitre_id,
        })

    return profiles


# =============================================================================
# SKILL 44: El Estratega MITRE ATT&CK — Upgraded vectorized Polars engine
# =============================================================================
def enrich_with_mitre_attck(df: pl.DataFrame, source_type: str = "auto") -> pl.DataFrame:
    """
    Enriches DataFrame with MITRE ATT&CK columns using fully vectorized
    Polars when().then() — zero Python loops, pure C/Rust speed.
    Adds: MITRE_Tactic, MITRE_ID, MITRE_Technique columns.
    """
    cols = df.columns

    if source_type == "auto":
        waf_indicators = {"ViolationCategory", "ClientIP", "SrcIP", "RequestPath",
                          "WAF_Rule", "AttackType", "Target_URI", "Triggered_Rule"}
        source_type = "waf" if waf_indicators & set(cols) else "evtx"

    df = df.with_columns([
        pl.lit("Unmapped").alias("MITRE_Tactic"),
        pl.lit("None").alias("MITRE_ID"),
        pl.lit("Unmapped").alias("MITRE_Technique"),
    ])

    if source_type == "waf":
        rule_col = next((c for c in ["Triggered_Rule", "ViolationCategory", "AttackType",
                                     "WAF_Rule", "RuleName", "forensic_category"] if c in cols), None)
        uri_col  = next((c for c in ["Target_URI", "URI", "RequestPath", "URL",
                                     "cs-uri-stem", "Path"] if c in cols), None)

        rule_expr = pl.col(rule_col).cast(pl.Utf8).str.to_lowercase() if rule_col else pl.lit("")
        uri_expr  = pl.col(uri_col).cast(pl.Utf8).str.to_lowercase()  if uri_col  else pl.lit("")

        df = df.with_columns([
            pl.when(rule_expr.str.contains(
                r"sqli|sql.injection|xss|lfi|rfi|rce|traversal|inject|command"
            )).then(pl.lit("Initial Access"))
            .when(uri_expr.str.contains(r"login|wp-login|admin|auth|signin|password|credential"))
            .then(pl.lit("Credential Access"))
            .when(rule_expr.str.contains(r"scan|probe|recon|nikto|nmap|masscan|spider"))
            .then(pl.lit("Reconnaissance"))
            .when(rule_expr.str.contains(r"dos|flood|slowloris|ddos|rate.limit"))
            .then(pl.lit("Impact"))
            .when(rule_expr.str.contains(r"ssrf|server.side|metadata|169\.254|internal"))
            .then(pl.lit("Collection"))
            .when(rule_expr.str.contains(r"xxe|deserializ|object.inject"))
            .then(pl.lit("Execution"))
            .otherwise(pl.col("MITRE_Tactic"))
            .alias("MITRE_Tactic"),

            pl.when(rule_expr.str.contains(r"sqli|sql.injection|xss|lfi|rfi|rce|traversal|inject"))
            .then(pl.lit("T1190"))
            .when(uri_expr.str.contains(r"login|admin|auth|signin|password"))
            .then(pl.lit("T1110"))
            .when(rule_expr.str.contains(r"ssrf|metadata|169\.254"))
            .then(pl.lit("T1602"))
            .when(rule_expr.str.contains(r"scan|probe|recon|nikto|nmap"))
            .then(pl.lit("T1595"))
            .when(rule_expr.str.contains(r"dos|flood|ddos"))
            .then(pl.lit("T1498"))
            .otherwise(pl.col("MITRE_ID"))
            .alias("MITRE_ID"),
        ])

    elif source_type == "evtx":
        eid_expr   = pl.col("EventID").cast(pl.Int64, strict=False) if "EventID" in cols else pl.lit(-1).cast(pl.Int64)
        cmd_expr   = pl.col("CommandLine").cast(pl.Utf8).str.to_lowercase() if "CommandLine" in cols else pl.lit("")
        proc_expr  = pl.col("ProcessName").cast(pl.Utf8).str.to_lowercase() if "ProcessName" in cols else pl.lit("")
        logon_expr = pl.col("LogonType").cast(pl.Int64, strict=False) if "LogonType" in cols else pl.lit(-1).cast(pl.Int64)
        ip_expr    = pl.col("IpAddress").cast(pl.Utf8) if "IpAddress" in cols else pl.lit("")

        df = df.with_columns([
            pl.when(
                (eid_expr == 4688) &
                cmd_expr.str.contains(r"-enc|-encodedcommand|bypass|hidden|iex|invoke-expression|downloadstring") &
                proc_expr.str.contains(r"powershell|pwsh")
            ).then(pl.lit("Execution"))
            .when((eid_expr == 4624) & logon_expr.is_in([3, 10]) & (~ip_expr.str.starts_with("127.")))
            .then(pl.lit("Lateral Movement"))
            .when(eid_expr.is_in([7045, 4698, 4702])).then(pl.lit("Persistence"))
            .when(eid_expr.is_in([1102, 104, 4719])).then(pl.lit("Defense Evasion"))
            .when(eid_expr.is_in([4769, 4768, 4771, 4776, 4625])).then(pl.lit("Credential Access"))
            .when(eid_expr.is_in([4648, 4672])).then(pl.lit("Privilege Escalation"))
            .otherwise(pl.col("MITRE_Tactic")).alias("MITRE_Tactic"),

            pl.when((eid_expr == 4688) & proc_expr.str.contains(r"powershell|pwsh")).then(pl.lit("T1059.001"))
            .when(eid_expr == 7045).then(pl.lit("T1543.003"))
            .when(eid_expr == 4698).then(pl.lit("T1053.005"))
            .when(eid_expr.is_in([1102, 104, 4719])).then(pl.lit("T1562.002"))
            .when(eid_expr.is_in([4769, 4768])).then(pl.lit("T1558.003"))
            .when(eid_expr.is_in([4771, 4776, 4625])).then(pl.lit("T1110"))
            .when((eid_expr == 4624) & logon_expr.is_in([3, 10])).then(pl.lit("T1021"))
            .when(eid_expr.is_in([4648, 4672])).then(pl.lit("T1078"))
            .otherwise(pl.col("MITRE_ID")).alias("MITRE_ID"),
        ])

    df = df.with_columns(
        pl.when(pl.col("MITRE_ID") != "None")
        .then(pl.concat_str([pl.col("MITRE_ID"), pl.lit(" — "), pl.col("MITRE_Tactic")]))
        .otherwise(pl.lit("Unmapped"))
        .alias("MITRE_Technique")
    )

    return df


def sub_analyze_hunting(df: pl.DataFrame) -> dict:

    """Hunting and Pattern Detection Sub-task"""
    hunt_data = apply_hunter_logic(df)
    stats = {"type": "hunting", "patterns": [], "network": [], "logons": []}
    
    if hunt_data["patterns"]:
        meta = hunt_data.get("_meta", {})
        for p in hunt_data["patterns"][:15]:
            ts = p.get(meta.get("ts_col")) if meta.get("ts_col") else (p.get("TrueEventTime") or p.get("EventTime") or "N/A")
            usr = p.get(meta.get("user_col")) if meta.get("user_col") else (p.get("ProcessUser") or "N/A")
            cmd = p.get(meta.get("cmd_col")) if meta.get("cmd_col") else p.get("ProcessCmd")
            cmd = (str(cmd) or "")[:250] # increased limit to preserve tactic tags
            row_id = p.get(meta.get("id_col")) if meta.get("id_col") else p.get("_id")
            stats["patterns"].append({"timestamp": ts, "user": usr, "command": cmd, "source_row_id": row_id})
    
    if hunt_data["network"].get("destinations"):
        for d in hunt_data["network"]["destinations"][:5]:
            stats["network"].append({"destination": d['Clean_Dst'], "count": d['count']})

    if hunt_data["network"].get("logons"):
        stats["logons"] = hunt_data["network"]["logons"][:5]
            
    return stats

def sub_analyze_identity_and_procs(df: pl.DataFrame) -> dict:
    """Identity and Process Summary Sub-task"""
    stats = {"type": "identity", "users": [], "hosts": [], "processes": [], "rare_processes": [], "rare_paths": []}
    user_col = next((c for c in df.columns if c.lower() in ["user", "username", "account"]), None)
    host_col = next((c for c in df.columns if c.lower() in ["computer", "computername", "host", "hostname"]), None)
    # Process column: prefer real process names, avoid "Task" (EVTX task category IDs)
    proc_col = next((c for c in df.columns if c.lower() in ["processname", "image", "process", "newprocessname", "parentprocessname"]), None)
    if not proc_col:
        # Fallback: "task" only if values look like paths/names, not pure numbers
        _task_col = next((c for c in df.columns if c.lower() == "task"), None)
        if _task_col:
            _sample = df.select(pl.col(_task_col).drop_nulls().head(20).cast(pl.Utf8)).to_series().to_list()
            _has_paths = any(("\\" in str(v) or "/" in str(v) or ".exe" in str(v).lower()) for v in _sample if v)
            if _has_paths:
                proc_col = _task_col
    path_col = next((c for c in df.columns if c.lower() in ["path", "filepath", "processpath", "imagepath", "folder"]), None)

    # Shared filter: exclude nulls, blanks, pure numbers, and sentinel values
    _bad_vals = {"none", "null", "", "-", "n/a", "nan", "unknown", "undefined", "0", "system idle process"}

    def _filter_meaningful(col_name):
        """Return a filtered LazyFrame excluding nulls, blanks, pure numeric and sentinel values."""
        return (df.lazy()
            .filter(pl.col(col_name).is_not_null())
            .filter(pl.col(col_name).cast(pl.Utf8).str.strip_chars() != "")
            .filter(~pl.col(col_name).cast(pl.Utf8).str.to_lowercase().is_in(list(_bad_vals)))
            .filter(~pl.col(col_name).cast(pl.Utf8).str.strip_chars().str.contains(r"^\d{1,5}$"))
            .collect())

    if user_col:
        u_counts = df.group_by(user_col).agg(pl.len().alias("count")).sort("count", descending=True).head(5)
        stats["users"] = [{"name": str(r[user_col]), "count": r['count']} for r in u_counts.iter_rows(named=True)]
    if host_col:
        h_counts = df.group_by(host_col).agg(pl.len().alias("count")).sort("count", descending=True).head(5)
        stats["hosts"] = [{"name": str(r[host_col]), "count": r['count']} for r in h_counts.iter_rows(named=True)]
    if proc_col:
        # Top processes (filtered — no nulls, blanks, or pure numeric values)
        try:
            df_proc = _filter_meaningful(proc_col)
            if df_proc.height > 0:
                p_counts = df_proc.group_by(proc_col).agg(pl.len().alias("count")).sort("count", descending=True).head(8)
                stats["processes"] = [{"name": row[proc_col], "count": row['count']} for row in p_counts.iter_rows(named=True)]
                # Rare processes (ascending sort = least common first)
                p_rare = df_proc.group_by(proc_col).agg(pl.len().alias("count")).sort("count", descending=False).head(5)
                stats["rare_processes"] = [{"name": row[proc_col], "count": row['count']} for row in p_rare.iter_rows(named=True)]
        except Exception:
            pass

    if path_col:
        try:
            df_path = _filter_meaningful(path_col)
            if df_path.height > 0:
                path_rare = df_path.group_by(path_col).agg(pl.len().alias("count")).sort("count", descending=False).head(5)
                stats["rare_paths"] = [{"name": str(row[path_col])[:100], "count": row['count']} for row in path_rare.iter_rows(named=True)]
        except Exception:
            pass
            
    return stats

def apply_hunter_logic(df: pl.DataFrame) -> dict:
    """
    Applies logic from 'chronos_hunter_summary' skill to a collected DataFrame.
    """
    res = {"identity": {}, "network": {}, "patterns": []}
    
    if df.is_empty():
        return res
        
    # 1. Identity
    try:
        host_col = next((c for c in df.columns if c.lower() in ["hostname", "computer", "computername"]), None)
        if host_col:
            res["identity"]["hosts"] = df.filter(pl.col(host_col).is_not_null()).group_by(host_col).agg(pl.len().alias("count")).sort("count", descending=True).head(10).to_dicts()
        
        user_col = next((c for c in df.columns if c.lower() in ["processuser", "user", "username", "accountname"]), None)
        if user_col:
            res["identity"]["users"] = df.filter(pl.col(user_col).is_not_null()).group_by(user_col).agg(pl.len().alias("count")).sort("count", descending=True).head(10).to_dicts()
    except Exception as e:
        logger.warning(f"Error in hunter identity logic: {e}")

    # 2. Network
    try:
        dst_col = next((c for c in df.columns if c.lower() in ["dst", "destinationip", "destination", "destip", "host"]), None)
        if dst_col:
            clean_df = df.with_columns(pl.col(dst_col).cast(pl.Utf8, strict=False).str.replace_all(r"\[|\]|'", "").alias("Clean_Dst"))
            res["network"]["destinations"] = clean_df.filter(pl.col("Clean_Dst").is_not_null() & (pl.col("Clean_Dst") != "")).group_by("Clean_Dst").agg(pl.len().alias("count")).sort("count", descending=True).head(10).to_dicts()
        
        # Add Logon Event Detection from Skills
        event_name_col = next((c for c in df.columns if c.lower() in ["eventid", "eventname", "task", "category"]), None)
        if event_name_col:
            logons = df.filter(pl.col(event_name_col).cast(pl.Utf8).str.to_lowercase().str.contains("logon|auth|access|signin"))
            if not logons.is_empty():
                res["network"]["logons"] = logons.group_by(event_name_col).agg(pl.len().alias("count")).sort("count", descending=True).to_dicts()
    except Exception as e:
        logger.warning(f"Error in hunter network logic: {e}")

    # 3. Suspicious Patterns (YARA-like TTPs)
    try:
        import re
        # Comprehensive TTP Regex patterns
        ttps = {
            "Execution/LOLBins": r"(?i)(wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe.*(javascript|vbscript|inetcpl|shell32)|regsvr32\.exe.*scrobj|certutil\.exe.*urlcache|bitsadmin\.exe.*transfer|msbuild\.exe.*\.xml|powershell.*(iex|invoke-expression|downloadstring|-enc|encodedcommand|bypass|hidden)|cmd\.exe\s+/c|sh\s+-c|bash\s+-c)",
            "Persistence": r"(?i)(schtasks.*/create|wevtutil.*cl|reg\s+(add|delete).*currentversion\\run|sc\s+create.*binpath|vssadmin.*delete\s+shadows)",
            "Credential Access": r"(?i)(mimikatz|sekurlsa|procdump.*lsass|ntdsutil.*ac\s+i.*ntds|tasklist.*lsass|shadowcopy|lsass\.dmp)",
            "Discovery": r"(?i)(\bwhoami\b|net\s+user|net\s+localgroup|net\s+group|nltest|ipconfig\s+/all|systeminfo|tasklist|netstat\s+-an|quser|qwinsta|adfind)",
            "Suspicious Paths": r"(?i)(\\temp\\|\\programdata\\|\\appdata\\local\\temp|/tmp/|/dev/shm/|/var/tmp/)",
            "Ransomware/Exfil": r"(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete.*catalog|rclone|megasync|filezilla|winscp)",
            "SQL Injection (OWASP/MITRE)": r"(?i)(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|waitfor\s+delay|exec\s+xp_cmdshell|1=1|%27%20OR%20)",
            "Cross-Site Scripting/XSS (OWASP/MITRE)": r"(?i)(<script>|javascript:|alert\(|onerror=|onload=|document\.cookie)",
            "Path Traversal/LFI (OWASP/MITRE)": r"(?i)(\.\./\.\./|%2e%2e%2f|/etc/passwd|windows\\win\.ini|boot\.ini)",
            "Command Injection (OWASP/MITRE)": r"(?i)(;\s*ls\s*-|\|\s*bash|`.*`|;\s*cat\s+/etc/)"
        }
        
        master_regex = "|".join([f"({pat})" for pat in ttps.values()])
        
        # Flexibly map the command/process/message column for various input types
        cmd_col = next((c for c in df.columns if c.lower() in ["processcmd", "commandline", "command", "cmdline", "process", "imagepath", "message", "description", "request", "uri", "details"]), None)
        
        if cmd_col:
            susp_df = df.filter(
                pl.col(cmd_col).cast(pl.Utf8, strict=False)
                .str.contains(master_regex)
                .fill_null(False)
            )
            
            if not susp_df.is_empty():
                ts_col = next((c for c in df.columns if c.lower() in ["trueeventtime", "eventtime", "time", "timestamp", "date", "@timestamp"]), None)
                proc_host_col = next((c for c in df.columns if c.lower() in ["hostname", "computer", "computername", "system", "host"]), None)
                proc_col = next((c for c in df.columns if c.lower() in ["processname", "image", "process", "task", "provider"]), None)
                u_col = next((c for c in df.columns if c.lower() in ["processuser", "user", "username", "accountname", "subjectusername"]), None)
                
                cols_to_select = []
                # Fallback to No. if _id is not present
                id_col = "_id" if "_id" in df.columns else ("No." if "No." in df.columns else None)
                if id_col: cols_to_select.append(id_col)
                if ts_col: cols_to_select.append(ts_col)
                if proc_host_col: cols_to_select.append(proc_host_col)
                if proc_col: cols_to_select.append(proc_col)
                if u_col: cols_to_select.append(u_col)
                cols_to_select.append(cmd_col)
                
                # Make sure columns are unique
                cols_to_select = list(dict.fromkeys(cols_to_select))
                
                # Apply extraction limit and deduplicate on the command column to remove noise
                patterns_list = susp_df.select(cols_to_select).unique(subset=[cmd_col], keep="first").head(30).to_dicts()
                
                # Tag occurrences with matching TTPs
                for row_dict in patterns_list:
                    cmd_value = str(row_dict.get(cmd_col, ""))
                    detected_tactic = "Malicious Activity"
                    for tactic, pat in ttps.items():
                        if re.search(pat, cmd_value):
                            detected_tactic = tactic
                            break
                    row_dict[cmd_col] = f"[{detected_tactic}] {cmd_value}"

                res["patterns"] = patterns_list
                res["_meta"] = {
                    "ts_col": ts_col,
                    "user_col": u_col,
                    "cmd_col": cmd_col,
                    "id_col": id_col
                }
    except Exception as e:
        logger.warning(f"Error in hunter patterns logic: {e}")
            
    return res


def ingest_json_file(file_path: str) -> pl.LazyFrame:
    """
    Safely ingests JSON files, handling both NDJSON and standard JSON arrays.
    Prevents OOM by converting large JSON arrays to NDJSON temporarily if needed.
    """
    try:
        # 1. Attempt NDJSON Scan first (Optimistic)
        try:
            lf = pl.scan_ndjson(file_path)
            lf.fetch(1)
            return lf
        except:
            pass

        # 2. Check if it's a standard JSON array
        with open(file_path, "rb") as f:
            first_byte = f.read(1)
            f.seek(0)
            
            if first_byte == b'[':
                # It's a JSON array. For small files, read_json is fine.
                # For large files, we need to stream it.
                file_size = os.path.getsize(file_path)
                if file_size < 100 * 1024 * 1024: # < 100MB
                    return pl.read_json(file_path).lazy()
                else:
                    # LARGE JSON ARRAY: Convert to NDJSON on the fly to avoid OOM
                    # This is a bit slow but safe.
                    tmp_ndjson = file_path + ".tmp.ndjson"
                    import ijson # We will hope it is available or fallback
                    
                    try:
                        import ijson
                        with open(file_path, "rb") as f_in, open(tmp_ndjson, "w") as f_out:
                            for item in ijson.items(f_in, "item"):
                                f_out.write(json.dumps(item) + "\n")
                        return pl.scan_ndjson(tmp_ndjson)
                    except ImportError:
                        # Fallback: Simple character-based chunking (Risky but better than OOM)
                        logger.warning("ijson not found. Using fallback JSON streaming.")
                        # This fallback is highly specific to a flat list of objects
                        return pl.read_json(file_path).lazy() 
            else:
                # Might be a single JSON object or malformed
                return pl.read_json(file_path).lazy()

    except Exception as e:
        logger.error(f"Ingestion error for {file_path}: {e}")
        raise e

def apply_standard_processing(lf: pl.LazyFrame, params: dict) -> pl.LazyFrame:
    """
    Unifies filtering, sorting, and indexing logic across all data endpoints.
    Params dict expected keys: query, col_filters, start_time, end_time, sort_col, sort_dir, selected_ids
    """
    # 1. Forensic Sanitization
    lf = sanitize_context_data(lf)
    
    schema = lf.collect_schema()
    all_cols = schema.names()
    
    # 2. Filters
    # Global Search — token-based AND search
    # Each space-separated token must appear in at least one column (AND logic between
    # tokens, OR logic across columns). Leading path separators (.\/\) are stripped from
    # tokens so queries like ".\jre\bin\javaw" match "poleo\jre\bin\javaw.exe".
    query = params.get('query')
    if query and query.strip():
        raw_tokens = query.strip().lower().split()
        # Build a clean token list: for each token try the stripped version first,
        # fall back to original if stripping leaves < 2 chars
        tokens = []
        for t in raw_tokens:
            stripped = t.lstrip('.\\/`\'"')
            tokens.append(stripped if len(stripped) >= 2 else t)
        tokens = [t for t in tokens if t]  # remove empties

        for token in tokens:
            try:
                lf = lf.filter(
                    pl.any_horizontal(
                        pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(token, literal=True).fill_null(False)
                        for c in all_cols
                    )
                )
            except Exception:
                # Fallback: iterative per-column OR
                col_exprs = []
                for c in all_cols:
                    try:
                        col_exprs.append(
                            pl.col(c).cast(pl.Utf8, strict=False).str.to_lowercase().str.contains(token, literal=True).fill_null(False)
                        )
                    except Exception:
                        continue
                if col_exprs:
                    lf = lf.filter(functools.reduce(operator.or_, col_exprs))

    # Column Filters
    col_filters = params.get('col_filters')
    if col_filters:
        # data endpoints might send JSON string or dict
        if isinstance(col_filters, str):
            try:
                col_filters = json.loads(col_filters)
            except:
                col_filters = []
        
        if isinstance(col_filters, list):
            # Form: [{'field': 'col', 'value': 'val', 'type': 'like'}]
            for f in col_filters:
                col = f.get('field')
                val = f.get('value')
                typ = f.get('type')
                if not col or val is None: continue
                
                c_expr = pl.col(col)
                if typ == "like":
                    lf = lf.filter(c_expr.cast(pl.Utf8).str.to_lowercase().str.contains(str(val).lower(), literal=True))
                elif typ in ["=", "=="]:
                    lf = lf.filter(c_expr.cast(pl.Utf8) == str(val))
                elif typ == "!=":
                     lf = lf.filter(c_expr.cast(pl.Utf8) != str(val))
                elif typ == ">":
                    lf = lf.filter(c_expr.cast(pl.Float64, strict=False) > float(val))
                elif typ == ">=":
                    lf = lf.filter(c_expr.cast(pl.Float64, strict=False) >= float(val))
                elif typ == "<":
                    lf = lf.filter(c_expr.cast(pl.Float64, strict=False) < float(val))
                elif typ == "<=":
                    lf = lf.filter(c_expr.cast(pl.Float64, strict=False) <= float(val))
                elif typ == "in":
                    if isinstance(val, str):
                        vals = [v.strip() for v in val.split(",")]
                    else:
                        vals = val if isinstance(val, list) else [val]
                    lf = lf.filter(c_expr.cast(pl.Utf8).is_in([str(v) for v in vals]))
                elif typ == "regex":
                    lf = lf.filter(c_expr.cast(pl.Utf8).str.contains(str(val), literal=False))
        elif isinstance(col_filters, dict):
            # Form: {'col': 'val'}
            for col, val in col_filters.items():
                if not col or val is None: continue
                lf = lf.filter(pl.col(col).cast(pl.Utf8).str.to_lowercase().str.contains(str(val).lower(), literal=True))

    # Selected IDs (for exports)
    selected_ids = params.get('selected_ids')
    if selected_ids:
        if isinstance(selected_ids, str):
            try:
                selected_ids = json.loads(selected_ids)
            except:
                selected_ids = []
        if isinstance(selected_ids, list) and len(selected_ids) > 0:
            _id_exists = "_id" in lf.collect_schema().names()
            if _id_exists:
                selected_ids_str = [str(x) for x in selected_ids]
                lf = lf.filter(pl.col("_id").cast(pl.Utf8).is_in(selected_ids_str))

    # Time Filter
    time_col = get_primary_time_column(all_cols)
    if time_col:
        lf = normalize_time_columns_in_df(lf)
        start_time = params.get('start_time')
        end_time = params.get('end_time')
        if start_time or end_time:
            time_fmt = "%Y-%m-%d %H:%M:%S"
            if start_time:
                p_start = parse_time_boundary(start_time)
                if p_start:
                    lf = lf.filter(pl.col(time_col).str.to_datetime(time_fmt, strict=False) >= pl.lit(p_start).dt.datetime())
            if end_time:
                p_end = parse_time_boundary(end_time)
                if p_end:
                     lf = lf.filter(pl.col(time_col).str.to_datetime(time_fmt, strict=False) <= pl.lit(p_end).dt.datetime())

    # 3. Baseline Sort (for stable IDs)
    if time_col:
        time_fmt = "%Y-%m-%d %H:%M:%S"
        lf = lf.with_columns(
            pl.col(time_col).cast(pl.Int64, strict=False).alias("_epoch_tmp_")
        ).with_columns(
            pl.when(pl.col("_epoch_tmp_") > 10**18).then(pl.from_epoch(pl.col("_epoch_tmp_"), time_unit="ns"))
            .when(pl.col("_epoch_tmp_") > 10**15).then(pl.from_epoch(pl.col("_epoch_tmp_"), time_unit="us"))
            .when(pl.col("_epoch_tmp_") > 10**12).then(pl.from_epoch(pl.col("_epoch_tmp_"), time_unit="ms"))
            .when(pl.col("_epoch_tmp_") > 10**8).then(pl.from_epoch(pl.col("_epoch_tmp_"), time_unit="s"))
            .otherwise(pl.col(time_col).str.to_datetime(time_fmt, strict=False))
            .alias("_ts_sort_")
        ).sort("_ts_sort_", descending=False).drop(["_ts_sort_", "_epoch_tmp_"])

    # 4. User Sort and Indexing
    sort_col = params.get('sort_col')
    sort_dir = params.get('sort_dir')
    
    if sort_col and sort_dir:
        _current_cols = lf.collect_schema().names()
        is_no_sort = (sort_col.lower() in ["no.", "_id"])
        desc_user = (sort_dir.lower() == 'desc')

        if is_no_sort:
            if "_id" in _current_cols:
                lf = lf.sort("_id", descending=desc_user)
        else:
            try:
                # Optimized sort: Try numeric first, then fallback to alpha
                lf = lf.sort(
                    by=[pl.col(sort_col).cast(pl.Float64, strict=False), pl.col(sort_col)], 
                    descending=[desc_user, desc_user]
                )
            except:
                lf = lf.sort(sort_col, descending=desc_user)
        
    return lf

def calculate_smart_risk_m4(df_parsed: pl.DataFrame, df_iocs: pl.DataFrame = None, sigma_hits: list = None) -> dict:
    """
    Skill de Antigravity: Calcula el nivel de riesgo contextual de la evidencia.
    Ignora el tamaño del archivo y se centra en la Inteligencia de Amenazas y 
    anomalías temporales usando Polars.
    """
    risk_score = 0
    risk_factors = []

    # ==========================================
    # 1. EVALUACIÓN DE IOCs (Peso: +50 puntos)
    # ==========================================
    # Si el motor extrajo URLs, IPs o patrones sospechosos previamente
    if df_iocs is not None and df_iocs.height > 0:
        risk_score += 50
        risk_factors.append(f"Se detectaron {df_iocs.height} posibles Indicadores de Compromiso (URLs/IPs extraídas). [+50 pts]")

    # ==========================================
    # 2. EVALUACIÓN DE TTPs / SIGMA (Peso: Variable)
    # ==========================================
    if sigma_hits:
        for hit in sigma_hits:
            level = hit.get('level', hit.get('severity', '')).lower()
            name = hit.get('title', hit.get('rule_name', 'Unknown Rule'))
            tech = hit.get('mitre_technique', '')
            rows = hit.get('matched_rows', 1)
            label = f"{name}" + (f" [{tech}]" if tech else "") + f" — {rows} evento(s)"
            if level == 'critical':
                risk_score += 100
                risk_factors.append(f"TTP Crítico: {label} [+100 pts]")
            elif level == 'high':
                risk_score += 60
                risk_factors.append(f"TTP Alto: {label} [+60 pts]")
            elif level == 'medium':
                risk_score += 30
                risk_factors.append(f"TTP Medio: {label} [+30 pts]")
            elif level == 'low':
                risk_score += 10
                risk_factors.append(f"TTP Bajo: {label} [+10 pts]")

    # ==========================================
    # 3. ANOMALÍA TEMPORAL M4 (Spike Detection)
    # ==========================================
    # Buscamos ráfagas (ej. ataques de fuerza bruta o DoS).
    # Usamos group_by_dynamic de Polars para agrupar por minuto a velocidad nativa.
    try:
        is_lazy = isinstance(df_parsed, pl.LazyFrame)
        cols = df_parsed.collect_schema().names() if is_lazy else df_parsed.columns
        time_col = next((c for c in cols if c.lower() in ["timestamp", "time", "date", "eventtime", "trueeventtime", "@timestamp"]), None)
        
        if time_col:
            # Polars exige que la tabla esté ordenada cronológicamente para group_by_dynamic
            try:
                lf_time = df_parsed.lazy() if not is_lazy else df_parsed
                lf_time = lf_time.select([time_col]).with_columns(pl.col(time_col).cast(pl.Utf8).str.to_datetime(strict=False)).drop_nulls(time_col).sort(time_col)
                df_time = lf_time.collect(streaming=True)
            except Exception:
                df_time = pl.DataFrame()
                
            if df_time.height > 0:
                spikes = (
                    df_time.group_by_dynamic(time_col, every="1m")
                    .agg(pl.len().alias("event_count"))
                )
                
                if spikes.height > 0:
                    mean_events = spikes.select(pl.col("event_count").mean()).item()
                    max_events = spikes.select(pl.col("event_count").max()).item()
                    
                    # Heurística de Pico: Si el minuto más activo tiene 5x más eventos que el promedio 
                    # y supera un umbral base (ej. 100 eventos/min), es una anomalía real.
                    if mean_events > 0 and max_events > (mean_events * 5) and max_events > 100:
                        risk_score += 20
                        peak_time = spikes.filter(pl.col("event_count") == max_events).select(pl.col(time_col).first()).item()
                        risk_factors.append(f"Anomalía Temporal: Ráfaga de {max_events} eventos/minuto detectada el {peak_time}. [+20 pts]")
    except Exception as e:
        risk_factors.append(f"Error al perfilar línea de tiempo: {str(e)}")

    # ==========================================
    # 4. RESOLUCIÓN DE NIVEL Y MAPEO PARA UI
    # ==========================================
    if risk_score >= 91:
        risk_level = "Critical"
        color_hex = "#FF4444" # Rojo
    elif risk_score >= 51:
        risk_level = "High"
        color_hex = "#FFBB33" # Naranja
    elif risk_score >= 21:
        risk_level = "Medium"
        color_hex = "#FFEB3B" # Amarillo
    else:
        risk_level = "Low"
        color_hex = "#00C851" # Verde

    # Si el archivo pesa mucho pero no disparó nada:
    if risk_score == 0:
        risk_factors.append("Tráfico benigno. Alto volumen de eventos atribuido a ruido de sistema o logs de depuración prolongados.")

    # Retornamos el diccionario listo para ser embebido en el JSON del botón 'Context'
    return {
        "Risk_Level": risk_level,
        "Risk_Score": risk_score,
        "UI_Color": color_hex,
        "Justification_Log": risk_factors,
        "Widget_Subtitle": "Based on IOCs & Threat Context"
    }

def extract_fallback_metrics(df: pl.DataFrame) -> dict:
    """
    Skill: Genera métricas de enriquecimiento (Top Usuarios, Top Rutas, Top Procesos)
    para alimentar los gráficos cuando no hay línea de tiempo.
    """
    metrics = {}
    
    # Extraemos las columnas que realmente existen en el DataFrame dinámicamente
    available_cols = df.columns

    # 1. Top Usuarios (Si la columna existe)
    if "user" in available_cols or "TargetUserName" in available_cols:
        col_name = "user" if "user" in available_cols else "TargetUserName"
        top_users = df.filter(pl.col(col_name).is_not_null()).group_by(col_name).len(name="count").sort("count", descending=True).head(5)
        metrics["Top_Users"] = top_users.to_dicts()

    # 2. Top Procesos / Archivos Anomalos
    if "process" in available_cols:
        top_processes = df.group_by("process").len(name="count").sort("count", descending=True).head(10)
        metrics["Top_Processes"] = top_processes.to_dicts()

    # 3. Top Rutas (Paths) - Usando regex rápido si están en un mensaje de texto
    if "message" in available_cols:
        path_regex = r"(/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)+)"
        paths_df = df.with_columns(pl.col("message").str.extract(path_regex, 1).alias("Extracted_Path")).drop_nulls(subset=["Extracted_Path"])
        if not paths_df.is_empty():
            top_paths = paths_df.group_by("Extracted_Path").len(name="count").sort("count", descending=True).head(5)
            metrics["Top_Paths"] = top_paths.to_dicts()

    return metrics

def generate_export_payloads(df: pl.DataFrame) -> dict:
    """
    Recibe un DataFrame (idealmente filtrado de la vista actual), extrae inteligencia accionable (URLs, IPs, Errores)
    y genera los payloads exactos para los botones 'Context' (JSON) y 'Graphical Report' (HTML).
    """
    try:
        if df.is_empty():
            return {"context_json": "{}", "html_data": {}}
            
        # 1. CHAIN OF CUSTODY
        # Ensure it has a reliable Row ID tracker if it doesn't already
        if "Source_Row_ID" not in df.columns:
            if "_id" in df.columns:
                df = df.with_columns(pl.col("_id").alias("Source_Row_ID"))
            else:
                df = df.with_row_index("Source_Row_ID")
        
        # Determine the columns to use. Try unified schema first, fallback to raw
        cols = df.columns
        msg_col = "Destination_Entity" if "Destination_Entity" in cols else ("message" if "message" in cols else [c for c in cols if df[c].dtype == pl.Utf8][0])
        proc_col = "Source_Entity" if "Source_Entity" in cols else ("process" if "process" in cols else "EventID" if "EventID" in cols else msg_col)
        time_col = "Time" if "Time" in cols else ("timestamp" if "timestamp" in cols else None)

        # 2. IOC EXTRACTION (URLs/IPs)
        ioc_regex = r"(https?://[^\s]+|\b(?:\d{1,3}\.){3}\d{1,3}\b)"
        
        try:
            df_iocs = (
                df.filter(pl.col(msg_col).str.contains(ioc_regex))
                .with_columns(
                    pl.col(msg_col).str.extract(ioc_regex, 1).alias("Extracted_IOC")
                )
            )
            urls_unique = df_iocs.select(pl.col("Extracted_IOC").n_unique()).item()
        except Exception:
            df_iocs = pl.DataFrame()
            urls_unique = 0

        # 3. ANOMALY DETECTION (Noise vs Signal)
        try:
            df_anomalies = (
                df.group_by(proc_col)
                .agg([
                    pl.count().alias("event_count"),
                    pl.col("Source_Row_ID").first().alias("first_seen_row"),
                    pl.col("Source_Row_ID").last().alias("last_seen_row")
                ])
                .filter(pl.col("event_count") > 50) 
                .sort("event_count", descending=True)
            )
            noise_detected = df_anomalies.height
        except Exception:
            df_anomalies = pl.DataFrame()
            noise_detected = 0

        # ==========================================
        # SIGMA ENGINE — Dynamic YAML rule matching
        # ==========================================
        sigma_hits = []
        try:
            from engine.sigma_engine import match_sigma_rules, load_sigma_rules
            sigma_rules = load_sigma_rules()
            sigma_hits = match_sigma_rules(df, sigma_rules)
        except Exception as _se:
            logger.debug(f"Sigma engine skipped in generate_export_payloads: {_se}")

        # ==========================================
        # SMART RISK ENGINE M4 CALCULATION
        # ==========================================
        # Calculate context-aware risk based on IOCs, Sigma hits, and temporal spikes
        risk_assessment = calculate_smart_risk_m4(df_parsed=df, df_iocs=df_iocs, sigma_hits=sigma_hits)

        # ==========================================
        # Enrich with sub-analyzer context (same data as HTML report)
        # ==========================================
        try:
            enriched_context = sub_analyze_context(df)
        except Exception:
            enriched_context = {}

        try:
            identity_data = sub_analyze_identity_and_procs(df)
        except Exception:
            identity_data = {}

        try:
            timeline_data = sub_analyze_timeline(df)
        except Exception:
            timeline_data = {}

        # ==========================================
        # PAYLOAD 1: JSON SOAR CONTEXT
        # ==========================================
        context_json = {
            "chronos_version": "Chronos-DFIR v1.1",
            "alert_summary": {
                "total_logs_analyzed": df.height,
                "unique_iocs_found": urls_unique,
                "noise_anomalies_detected": noise_detected,
                "risk_assessment": risk_assessment
            },
            "actionable_iocs": df_iocs.select(["Source_Row_ID", time_col, proc_col, "Extracted_IOC"]).to_dicts() if not df_iocs.is_empty() and time_col else [],
            "system_noise_summary": df_anomalies.to_dicts() if not df_anomalies.is_empty() else [],
            "fallback_metrics": extract_fallback_metrics(df),
            "forensic_context": {
                "top_users": enriched_context.get("users", []),
                "top_ips": enriched_context.get("ips", []),
                "top_hosts": enriched_context.get("hosts", []),
                "top_processes": enriched_context.get("processes", []),
                "top_paths": enriched_context.get("paths", []),
                "event_ids": enriched_context.get("event_ids", []),
                "tactics": enriched_context.get("tactics", []),
                "threat_actors": enriched_context.get("threat_actors", []),
                "violations": enriched_context.get("violations", []),
            },
            "timeline": {
                "time_range": timeline_data.get("time_range", "N/A"),
                "peaks": timeline_data.get("peaks", []),
                "eps": timeline_data.get("eps", 0),
            },
            "identity_analysis": identity_data if isinstance(identity_data, dict) else {},
            "sigma_detections": sigma_hits
        }

        # ==========================================
        # PAYLOAD 2: HTML REPORT (Mini-Tables)
        # ==========================================
        html_tables = {
            "Critical_Findings_Table": context_json["actionable_iocs"],
            "Anomalous_Processes_Table": context_json["system_noise_summary"],
            "Sigma_Hits_Table": sigma_hits
        }
        
        import json
        return {
            "context_json": json.dumps(context_json, indent=4),
            "html_data": html_tables
        }
        
    except Exception as e:
        import traceback
        trace_str = traceback.format_exc()
        import json
        return {
            "context_json": json.dumps({"error": str(e), "trace": trace_str}),
            "html_data": {"error": str(e)}
        }
