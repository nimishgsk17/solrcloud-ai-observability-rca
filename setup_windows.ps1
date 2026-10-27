# Execute from PowerShell in this project folder:
# powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
$ErrorActionPreference = "Stop"
Write-Host "Creating an isolated Python 3.12 environment ..."
py -3.12 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "Python 3.12 isn't available. Run 'py -0p' to list installed versions." }
Write-Host "Installing dashboard and LangGraph packages ..."
.\.venv\Scripts\python.exe -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Package installation failed" }
Write-Host "Checking compatible dependency versions ..."
.\.venv\Scripts\python.exe -m pip check
if ($LASTEXITCODE -ne 0) { throw "Dependency mismatch detected" }
.\.venv\Scripts\python.exe -c "import numpy, pyarrow, streamlit, langgraph; print('NumPy',numpy.__version__,'| PyArrow',pyarrow.__version__,'| Streamlit',streamlit.__version__,'| LangGraph import OK')"
Write-Host "Ready. Run: .\.venv\Scripts\python.exe -m streamlit run app.py"
