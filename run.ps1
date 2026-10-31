$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
python scripts/configure.py
if (-not (Test-Path '.venv/Scripts/python.exe')) {
    python -m venv .venv
}
& .venv/Scripts/python.exe -m pip install --disable-pip-version-check -r requirements.txt
$previousLive = $env:SWEETBERRY_LIVE
$env:SWEETBERRY_LIVE = 'false'
$backend = Start-Process -FilePath "$PSScriptRoot/.venv/Scripts/python.exe" -ArgumentList '-m','uvicorn','app.api:from_environment','--factory','--host','127.0.0.1','--port','8000' -WindowStyle Hidden -PassThru
try {
    & .venv/Scripts/python.exe -m uvicorn dashboard.server:app --host 127.0.0.1 --port 8501
} finally {
    Stop-Process -Id $backend.Id -ErrorAction SilentlyContinue
    $env:SWEETBERRY_LIVE = $previousLive
}
