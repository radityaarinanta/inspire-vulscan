# Contributing to INSPIRE

Thank you for your interest in contributing to **INSPIRE Security Suite**! As an open-source cybersecurity assessment tool, we welcome contributions from security researchers, developers, and enthusiasts.

Please take a moment to review this document before submitting contributions.

---

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please maintain a welcoming, inclusive, and professional environment.

---

## How Can I Contribute?

You can contribute to INSPIRE in several ways:
1. **Reporting Bugs**: Submitting detailed bug reports with reproduction steps.
2. **Suggesting Features**: Proposing new vulnerability detection modules, heuristics, or UI capabilities.
3. **Writing Detection Modules**: Expanding heuristic signatures for SQLi, XSS, security headers, or client-side malware.
4. **Improving Documentation**: Fixing typos, providing deployment guides, or clarifying scanner behavior.
5. **Code Optimization**: Enhancing asynchronous throughput, memory efficiency, or frontend responsiveness.

---

## Development Setup

### Prerequisites
* Python 3.10, 3.11, or 3.12
* Git

### Local Setup Instructions

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/inspire-vulscan.git
   cd inspire-vulscan
   ```

2. **Create a Virtual Environment**:
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Launch the Local Development Server**:
   ```bash
   python run.py
   ```
   The dashboard will automatically open at `http://127.0.0.1:8000`.

---

## Pull Request (PR) Workflow

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/new-detection-module
   # or
   git checkout -b fix/issue-description
   ```

2. **Coding Standards & Best Practices**:
   * **PEP 8 Compliance**: Write clean, readable, Pythonic code.
   * **Type Annotations**: Use Python type hinting (`typing` module / Pydantic models).
   * **AsyncIO Conventions**: Use `async`/`await` and non-blocking I/O for network operations.
   * **No Emojis Policy**: Maintain 0 emoji characters across code, comments, logs, and UI components.
   * **Safety First**: Payloads and heuristics must remain non-destructive and safe for testing.

3. **Run Verification & Tests**:
   Ensure all modules and reporters execute cleanly without errors:
   ```bash
   python cli.py https://httpbin.org -p quick --all-reports
   python cli.py http://127.0.0.1:8000/demo/malware-sample -m malware
   ```

4. **Commit and Push**:
   Use clear, descriptive commit messages:
   ```bash
   git commit -m "feat(malware): add WebAssembly cryptominer signature heuristics"
   git push origin feature/new-detection-module
   ```

5. **Open a Pull Request**:
   Fill out the provided Pull Request template and describe your changes thoroughly.
