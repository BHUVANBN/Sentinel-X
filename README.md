# SENTINEL-X: AI-Driven Threat Detection & Response

**SENTINEL-X** is a production-grade, local-first Security Operations Center (SOC) designed to monitor, detect, and respond to real-world cyber attacks across Linux, Windows, and macOS. It combines traditional rule-based detection with advanced correlation logic and AI-powered alert explainability.

---

## 🚀 Vision
> "A lightweight, explainable SOC that behaves identically to commercial EDR/XDR products, deployable locally with zero cloud dependency."

## ✨ Key Features

### 🔍 Multi-Layered Detection
- **Normalization Layer**: Converts disparate OS events into a unified **Elastic Common Schema (ECS)** compatible format.
- **Detection Engine**: Evaluates events against sliding-window thresholds (e.g., Brute Force, Port Scanning).
- **Correlation Engine**: Links related alerts (e.g., *Credential Access → Lateral Movement*) to detect multi-stage attack chains.

### 🤖 AI Narrative Engine
- **Explainable Alerts**: Uses Claude API or local Ollama (Llama 3) to generate human-language explanations for every alert.
- **MITRE ATT&CK Mapping**: Automatically maps every detection to specific tactics and techniques in the MITRE framework.

### ⚡ Active Response
- **OS-Aware Mitigation**: Proposes platform-specific actions like IP blocking (`iptables`/`netsh`), process termination, and account locking.
- **Human-in-the-loop**: All response actions require explicit approval via the dashboard before execution.

### 🖥️ Premium SOC Dashboard
- **Real-time Monitoring**: WebSocket-driven live metrics (CPU, Memory, Network) and scrolling alert feed.
- **Threat Matrix**: Interactive MITRE ATT&CK heatmap showing detected techniques.
- **Response Center**: A dedicated interface for reviewing and approving mitigation actions.

---

## 🛠️ Installation & Setup

### 1. Requirements
- Python 3.11+
- Node.js 18+ (for dashboard build)
- Root/Administrator privileges (for monitoring and response)

### 2. Fast Install
```bash
# Clone the repository
git clone https://github.com/user/sentinel-x
cd sentinel-x

# Install Python environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Build Dashboard
cd dashboard
npm install
npm run build
cd ..
```

### 3. Configuration
Edit `config/sentinel.yaml` to set your preferences. 
To use AI Narratives, provide your API key:
```yaml
llm:
  provider: anthropic
  api_key: "your-api-key"
```

### 4. Run SENTINEL-X
```bash
# Start the full system
python -m sentinel
```
Visit **http://localhost:8000** to access the dashboard.

---

## 🧪 Simulation & Testing
SENTINEL-X comes with a built-in attack simulator to test your defenses safely:
- `python -m sentinel --test-mode`
- Access the **Configuration** page in the dashboard to run:
    - **SSH Brute Force**
    - **Data Exfiltration**
    - **Ransomware Indicators**
    - **Full Attack Chain**

---

## 🏗️ Project Structure
```text
├── agents/             # OS Collectors (Linux, Windows, MacOS)
├── api/                # FastAPI Hub & WebSockets
├── config/             # YAML Rules & System Settings
├── correlation/        # Multi-signal link logic
├── dashboard/          # React 18 / Vite Frontend
├── detection/          # Rule Engine & Aggregation
├── explainability/     # AI Narrator & MITRE Mapper
├── normalizer/         # ECS Schema & Parsers
├── response/           # Mitigation Engine
└── storage/            # SQLAlchemy / SQLite Backend
```

## 📜 License
MIT © 2025 SENTINEL-X Team
