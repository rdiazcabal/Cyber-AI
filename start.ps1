cd "C:\Users\Rigo Diaz\Documents\Personales\Cyber-AI"

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\venv\Scripts\Activate.ps1

python -m uvicorn app.main:app --reload --port 8000