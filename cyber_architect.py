import json

class CyberArchitectSkill:
    """
    Skill de Especialista en Ciber-Estética y Optimización M4.
    Proporciona reglas de decisión para la implementación de UI/UX en herramientas de Ciberseguridad.
    """

    def __init__(self):
        self.name = "Cyber_Architect_Heuristics"
        self.version = "2.0.0-M4-Optimized"

    def get_component_specs(self, component_type: str, data_volume: str = "medium"):
        """
        Devuelve las especificaciones técnicas y estéticas para cualquier componente de UI.
        
        Args:
            component_type: ['table', 'chart', 'button', 'status_card', 'log_viewer']
            data_volume: ['low', 'medium', 'high', 'massive']
        """
        
        specs = {
            "table": {
                "decision_logic": "Si volume > high, usar virtual scrolling (Canvas-based). No renderizar más de 50 nodos DOM simultáneos.",
                "aesthetic_rules": "Bordes 1px #38bdf833, Zebra-striping con opacidad 0.02, Font: JetBrains Mono 12px.",
                "m4_optimization": "Aprovechar 'content-visibility: auto' para ceder ciclos de GPU al hilo principal."
            },
            "chart": {
                "decision_logic": "Para series temporales de incidentes, usar WebGL (Echarts o Three.js). Evitar SVG para más de 1000 puntos.",
                "aesthetic_rules": "Gradients de #38bdf8 a #818cf8 con efecto glow (drop-shadow). Sin grids ruidosas.",
                "m4_optimization": "OffscreenCanvas para renderizado de gráficas en un Web Worker independiente."
            },
            "button": {
                "decision_logic": "Solo dos estados: 'Action' (Sólido) y 'Neutral' (Outlined). Feedback háptico visual inmediato.",
                "aesthetic_rules": "Esquinas de 2px (Brutalismo), transiciones de 150ms, hover con scanline effect.",
                "m4_optimization": "Will-change: transform para pre-promoción de capa en la GPU."
            },
            "log_viewer": {
                "decision_logic": "Streaming buffer de texto. Resaltado de sintaxis (Regex) limitado a líneas visibles.",
                "aesthetic_rules": "Fondo #020617 (OLED Black), colores ANSI estándar de terminal forense.",
                "m4_optimization": "Uso de SharedArrayBuffer para comunicación entre el parser de logs (Python/Wasm) y la UI."
            }
        }

        return specs.get(component_type, {"error": "Componente no definido en la heurística de arquitectura."})

    def get_brand_identity(self):
        """Define la esencia visual que Antigravity debe proyectar."""
        return {
            "philosophy": "La seguridad es claridad. El diseño debe reducir la carga cognitiva del analista.",
            "color_palette": {
                "background": "#020617", # Deep Space
                "primary": "#38bdf8",    # Cyber Blue
                "critical": "#ef4444",   # Incident Red
                "success": "#22c55e",    # Integrity Green
                "neutral": "#64748b"     # Slate Gray
            },
            "typography": {
                "main": "Inter",
                "data": "JetBrains Mono"
            },
            "narrative_intent": "Transmitir omnisciencia sobre la red y control absoluto sobre la evidencia."
        }

    def validate_implementation(self, implementation_plan: str):
        """
        Actúa como revisor de código/diseño. 
        Analiza si un plan de implementación cumple con el 'Buen Gusto' y la 'Eficiencia'.
        """
        # Esta lógica sería consumida internamente por el Agente para auto-corregirse.
        check_list = [
            "¿Usa aceleración por GPU para elementos dinámicos?",
            "¿La paleta de colores respeta los contrastes de ciberseguridad?",
            "¿El peso del DOM está optimizado para evitar cuellos de botella en el M4?",
            "¿La historia que cuenta el diseño es coherente con el IR (Incident Response)?"
        ]
        return {"checks": check_list}

# Instancia para uso del sistema Antigravity
architect = CyberArchitectSkill()
if __name__ == "__main__":
    print(json.dumps(architect.get_brand_identity(), indent=2))
