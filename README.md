# Setting Up a Python Virtual Environment

A Python virtual environment is an isolated environment that allows you to manage dependencies for a specific project without affecting system-wide Python packages.

---

## 1. Check Python Installation

Make sure Python 3.8+ is installed:

```bash
python3 --version
```

or on some systems:

```bash
python --version
```

---

## 2. Create a Virtual Environment

In your project directory, run:

```bash
python3 -m venv .venv
```

This will create a folder named `venv` containing the isolated environment.

---

## 3. Activate the Virtual Environment

- **Linux / macOS**:

```bash
source .venv/bin/activate
```

- **Windows (PowerShell)**:

```powershell
.venv\Scripts\Activate.ps1
```

- **Windows (Command Prompt)**:

```cmd
.venv\Scripts\activate.bat
```

When activated, your shell prompt will usually show `(venv)` at the beginning.

---

## 4. Install Dependencies

Once activated, install project dependencies with:

```bash
pip install -r requirements.txt
```

Or install packages individually, e.g.:

```bash
pip install scapy
```

---

## 5. Deactivate the Environment

When you are done working, deactivate with:

```bash
deactivate
```

---

## 6. Delete the Virtual Environment (Optional)

If you no longer need the environment:

```bash
rm -rf .venv
```

(on Linux/macOS)

or

```powershell
rmdir /s .venv
```

(on Windows PowerShell)

---

## Notes

- Always activate the virtual environment before running project scripts.  
- Keep a `requirements.txt` file to make it easy for others to install dependencies:

```bash
pip freeze > requirements.txt
```
