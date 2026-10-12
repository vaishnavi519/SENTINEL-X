
# SENTINEL-X 🛡️
### AI Security Middleware & Document Threat Scanner

SENTINEL-X is an AI security middleware project designed to analyze user inputs and uploaded documents for potential security threats. It helps identify prompt injection attempts, sensitive information, exposed secrets, toxic content, and other security risks through a structured analysis pipeline.

## ✨ Features

- **Document Scanner:** Upload PDF, DOCX, and TXT files for security analysis.
- **Prompt Injection Detection:** Identify potentially malicious instructions embedded in text and documents.
- **Sensitive Information Detection:** Help identify personally identifiable information (PII).
- **Secret Detection:** Flag potentially exposed credentials and secrets.
- **Toxicity Analysis:** Analyze text for potentially harmful content.
- **Risk Assessment:** Generate a structured security report with risk information and decisions.
- **Secure Chat:** Analyze chat inputs through the security pipeline.
- **Quarantine & Audit:** Review quarantined items and audit records.

## 🧰 Tech Stack

- **Frontend:** React, JavaScript, Vite
- **Backend:** Python, FastAPI
- **API Communication:** REST API
- **Document Processing:** pypdf, python-docx
- **File Uploads:** Multipart form data

## 📂 Project Structure

```text
SENTINEL-X/
├── backend/
│   └── app/
│       ├── api/
│       │   ├── analyze.py
│       │   ├── document.py
│       │   ├── chat.py
│       │   └── audit.py
│       └── main.py
│
├── frontend/
│   └── src/
│       ├── api/
│       │   └── sentinel.js
│       ├── components/
│       │   └── Sidebar.jsx
│       ├── pages/
│       │   └── DocumentScanner.jsx
│       └── App.jsx
│
└── README.md
```

## ⚙️ Prerequisites

Install the following before running the project:

- Python 3.12 or a compatible version
- Node.js and npm
- Git

## 🚀 Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/vaishnavi519/SENTINEL-X.git
cd SENTINEL-X
```

### 2. Set up the backend

Open a terminal in the project directory:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the backend dependencies:

```powershell
pip install -r requirements.txt
```

Start the backend server:

```powershell
python -m uvicorn app.main:app --reload
```

The backend will usually be available at:

http://localhost:8000

API documentation:

http://localhost:8000/docs

### 3. Set up the frontend

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually:

http://localhost:5173

## 📄 How to Use the Document Scanner

1. Start both the backend and frontend servers.
2. Open SENTINEL-X in your browser.
3. Select **Document Scanner** from the sidebar.
4. Click **Choose File** and select a PDF, DOCX, or TXT document.
5. Click **Scan Document** to start the security analysis.
6. Review the generated security report, including the available risk information and analysis results.

**Note:** The document scanner extracts text from supported files. Image-only or scanned PDFs may require OCR before their contents can be analyzed.

## 🔌 Document Scanner API

**Endpoint:**

```http
POST /api/v1/analyze/document
```

The endpoint accepts a document as multipart form data using the field name `file`.

Supported file types: PDF, DOCX, TXT.

Maximum upload size: 10 MB.

## 🔐 Security & Privacy

- Do not commit API keys, passwords, access tokens, or `.env` files.
- Uploaded documents may contain sensitive information; use appropriate test data.
- File analysis results should be reviewed before making security decisions.
- Detection results are not guaranteed to identify every threat.

## 🛣️ Future Improvements

- OCR support for scanned documents
- Drag-and-drop document uploads
- Downloadable security reports
- Additional file-format support
- Improved detection and risk visualization
- Automated security testing

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Open a pull request.



**SENTINEL-X — Analyze. Detect. Protect.**
