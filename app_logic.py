import os
import sys
import logging
import asyncio
from typing import Dict, Any

logger = logging.getLogger("Chronos-Bridge")

# Base path for skills — configurable via env var, falls back to .agents/skills relative to this file
_DEFAULT_SKILLS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agents", "skills")
CODIFICACION_SKILLS = os.environ.get("CHRONOS_SKILLS_PATH", _DEFAULT_SKILLS_PATH)

def setup_bridge():
    """Adds necessary skills directories to sys.path"""
    skills_to_load = [
        "chronos_master_analyzer",
        "context_event_sanitizer",
        "chronos_hunter_summary",
        "chronos_telemetry_parser"
    ]
    
    for skill in skills_to_load:
        skill_path = os.path.join(CODIFICACION_SKILLS, skill)
        if os.path.exists(skill_path) and skill_path not in sys.path:
            sys.path.append(skill_path)

# Initialize
setup_bridge()

try:
    # Bridge to the Orchestrator Skill
    from orchestrator import chronos_master_analyzer as _orchestrate
    
    async def chronos_master_analyzer(file_path: str, **kwargs) -> Dict[str, Any]:
        """
        Master bridge that uses the chronos_master_analyzer skill.
        It automatically provides the sub-analysis functions from engine.forensic
        to main synergy between local app and specialized skills.
        """
        try:
            from engine.forensic import sub_analyze_timeline, sub_analyze_context, sub_analyze_hunting
            return await _orchestrate(file_path, sub_analyze_timeline, sub_analyze_context, sub_analyze_hunting, **kwargs)
        except Exception as e:
            logger.error(f"Error calling skill orchestrator: {e}")
            # Fallback to a basic result
            return {"status": "error", "message": str(e)}

except ImportError:
    logger.warning("Skill 'chronos_master_analyzer' not found in path. Using fallback.")
    async def chronos_master_analyzer(*args, **kwargs):
        return {"status": "error", "message": "Skill orchestrator not found"}

# Bridge to Sanitizer Skill
def get_sanitizer_skill():
    try:
        from sanitizer import sanitize_context_data
        return sanitize_context_data
    except ImportError:
        return None

# Bridge to Hunter Skill
def get_hunter_skill():
    try:
        from hunter import chronos_hunter_summary
        return chronos_hunter_summary
    except ImportError:
        return None
