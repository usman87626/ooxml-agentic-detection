"""
loader.py — Loads YAML instruction prompts for LLM agents.
"""
import yaml
from pathlib import Path
from agents.guardrails import build_system_guardrail

INSTRUCTIONS_DIR = Path(__file__).parent

def load_instruction(name: str) -> str:
    """Read a YAML instruction file and format it into a complete system prompt."""
    yaml_path = INSTRUCTIONS_DIR / f"{name}.yaml"
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    parts = [build_system_guardrail(), "\n\n"]
    
    if "responsibility" in data:
        parts.append(f"{data['responsibility'].strip()}\n\n")
        
    if "policy" in data:
        parts.append("RULES / POLICIES:\n")
        parts.append(f"{data['policy'].strip()}\n\n")
        
    if "input_format" in data:
        parts.append("INPUT FORMAT:\n")
        parts.append(f"{data['input_format'].strip()}\n\n")
        
    if "output_format" in data:
        parts.append("OUTPUT FORMAT:\n")
        parts.append(f"{data['output_format'].strip()}\n")
        
    return "".join(parts).strip()
