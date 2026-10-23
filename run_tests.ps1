# Runs the full test suite in Docker and writes an HTML report to test-results\report.html.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

docker build -q -t netaudit-dev -f docker/dev.Dockerfile docker | Out-Null
docker run --rm -t -v "${PSScriptRoot}:/src" -v netaudit-build:/build netaudit-dev bash /src/tools/run_tests.sh
if ($LASTEXITCODE -ne 0) { Write-Host "Tests failed (exit $LASTEXITCODE)" -ForegroundColor Red }

python tools/make_report.py test-results
Write-Host "Report: $PSScriptRoot\test-results\report.html" -ForegroundColor Green
