# PipelineLens local launcher.
# Starts the read-only API (loopback) and the Streamlit dashboard, then opens the browser.
# Usage:  ./run_local.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$python = 'C:\Python313\python.exe'

$env:PYTHONPATH = "$root\src"
$env:PIPELINELENS_LLM_MODE = 'disabled'
$env:PIPELINELENS_ALLOW_PRIVATE_CONTEXT = 'false'
$env:PIPELINELENS_API_URL = 'http://127.0.0.1:8000'

# API on 127.0.0.1:8000 (localhost-only inspection endpoints).
Start-Process -FilePath $python -WorkingDirectory $root -ArgumentList @(
    '-m', 'uvicorn', 'pipelinelens.api.main:app', '--host', '127.0.0.1', '--port', '8000'
)

# Dashboard on 127.0.0.1:8501. fileWatcherType=none avoids the Windows watcher crash.
Start-Process -FilePath $python -WorkingDirectory $root -ArgumentList @(
    '-m', 'streamlit', 'run', 'src/pipelinelens/dashboard/app.py',
    '--server.address', '127.0.0.1', '--server.port', '8501',
    '--server.fileWatcherType', 'none', '--browser.gatherUsageStats', 'false'
)

Start-Sleep -Seconds 2
Start-Process 'http://127.0.0.1:8501'
Write-Host 'PipelineLens starting: API http://127.0.0.1:8000  Dashboard http://127.0.0.1:8501'
