import os
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "SENTINEL_X_TECHNICAL_REPORT.txt")

EXCLUDE_DIRS = {".venv", "__pycache__", ".git", ".pytest_cache", "node_modules", "dist", ".next", "build"}
EXCLUDE_FILES = {"SENTINEL_X_TECHNICAL_REPORT.txt", "package-lock.json", "yarn.lock"}
EXCLUDE_EXTS = {".pyc", ".png", ".jpg", ".jpeg", ".ico", ".svg", ".db", ".sqlite", ".db-journal", ".webp"}

def get_tree(path, prefix=""):
    tree = ""
    items = sorted(os.listdir(path))
    # Filter items
    items = [i for i in items if i not in EXCLUDE_DIRS and i not in EXCLUDE_FILES and not any(i.endswith(ext) for ext in EXCLUDE_EXTS)]
    
    for i, item in enumerate(items):
        full_path = os.path.join(path, item)
        is_last = (i == len(items) - 1)
        connector = "└── " if is_last else "├── "
        
        if os.path.isdir(full_path):
            tree += f"{prefix}{connector}{item}/\n"
            new_prefix = prefix + ("    " if is_last else "│   ")
            tree += get_tree(full_path, new_prefix)
        else:
            tree += f"{prefix}{connector}{item}\n"
    return tree

def generate_report():
    print(f"Generating technical report for: {PROJECT_ROOT}")
    
    header = f"""============================================================
SENTINEL-X TECHNICAL IMPLEMENTATION REPORT
============================================================
Document Type: Full Technical Specification & Code Dump
Version: 2.1.0 (Hackathon Optimized)
Date: {datetime.now().strftime('%B %d, %Y')}
Status: PRODUCTION READY - PROBLEM STATEMENT 3 COMPLIANT
============================================================

1. EXECUTIVE SUMMARY
------------------------------------------------------------
SENTINEL-X is a high-throughput Security Operations Center (SOC) framework
designed for real-time threat detection, cross-layer correlation, and 
AI-driven explainability. 

The system has been specifically hardened for Hack Malenadu '26, focusing on:
- High-efficiency asynchronous event ingestion (1000+ ev/s).
- Strategic focus on 4 core threat categories (Brute Force, Lateral, Exfil, C2).
- AI-powered forensic narratives with OS-specific mitigation playbooks.
- Integrated self-validation and data replay (CICIDS 2017).

2. SYSTEM ARCHITECTURE
------------------------------------------------------------
SENTINEL-X operates on a 7-layer security stack:
- LAYER 1: MONITORING (Multi-Platform Agents: Linux, Win, Mac)
- LAYER 2: NORMALIZATION (ECS-Compatible schema mapper)
- LAYER 3: DETECTION (Asynchronous YAML-based rule evaluation)
- LAYER 4: CORRELATION (Multi-signal logic with Diversity Boosting)
- LAYER 5: EXPLAINABILITY (AI Narrator + Full MITRE ATT&CK Mapping)
- LAYER 6: RESPONSE (Human-in-the-loop OS-aware SOAR)
- LAYER 7: DASHBOARD (React 18 Premium SOC Visualizer)

3. FOLDER STRUCTURE
------------------------------------------------------------
{get_tree(PROJECT_ROOT)}

4. FULL SOURCE CODE
------------------------------------------------------------
"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        
        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Prune dirs
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in sorted(files):
                if file in EXCLUDE_FILES or any(file.endswith(ext) for ext in EXCLUDE_EXTS):
                    continue
                
                rel_path = os.path.relpath(os.path.join(root, file), PROJECT_ROOT)
                f.write(f"\n\nFILE: {rel_path}\n" + "="*80 + "\n")
                
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8") as code_f:
                        f.write(code_f.read())
                except Exception as e:
                    f.write(f"ERROR READING FILE: {e}")
                
                f.write("\n" + "="*80 + "\n")

    print(f"Report generated successfully: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_report()
