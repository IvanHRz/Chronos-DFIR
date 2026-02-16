# Chronos DFIR ⏳

Web-based timeline analysis tool for Digital Forensics and Incident Response. Handles large datasets (EVTX, CSV) with high-performance filtering, visualization, and export capabilities.

## 🚀 Features

- **High Performance**: Optimized for large files (tested with 2GB+ CSVs).
- **Format Support**: EVTX, CSV, JSON, Parquet, SQLite.
- **Smart Timeline**: Interactive histogram with zoom, pan, and click-to-filter.
- **Advanced Filtering**:
  - Global Search (RegEx supported)
  - Column-specific filtering (Server-side)
  - Time range selection
- **Split Export**: Break large datasets into manageable chunks (99MB parts) for external tools.
- **Standardization**: Auto-normalizes timestamps and column names.

---

## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/IvanHRz/Chronos-DFIR.git
cd Chronos-DFIR
```

### 2. Create Virtual Environment
It's recommended to use a virtual environment to avoid conflicts.

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### 1. Start the Server
Run the application using Uvicorn:

```bash
# Production mode (faster)
uvicorn app:app --host 0.0.0.0 --port 8000

# Development mode (auto-reload)
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### 2. Access the Web Interface
Open your browser and navigate to:
👉 **http://localhost:8000**

### 3. Load Data
- Drag & Drop your file (EVTX, CSV, etc.) into the drop zone.
- Click **"Process Artifact"**.
- Wait for the chart and table to load.

---

## 🧩 Key Functionalities

### 🔍 Filtering
- **Time Range**: Click and drag on the chart to zoom in. The table updates automatically.
- **Column Filter**: Type in any column header (e.g., EventID `4624`) and press Enter.
- **Global Search**: Use the top search bar for text search across all columns.

### 📦 Exporting
- **Split CSV**: If your file is too large for Excel/Timeline Explorer, use the **"Split (Zip)"** button. It will generate a ZIP file containing 99MB chunks of your filtered data.
- **Download View**: Export just the current table view (filtered) as CSV or XLSX.
