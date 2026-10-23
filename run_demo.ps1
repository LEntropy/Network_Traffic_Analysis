# Builds and starts the interactive test client at http://localhost:8000 (Ctrl+C to stop).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

docker build -t netaudit-demo -f docker/demo.Dockerfile .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Start-Process "http://localhost:8000"
# Published on 127.0.0.1 only, so the demo is not reachable from other machines.
docker run --rm -it --name netaudit-demo -p 127.0.0.1:8000:8000 --cap-add NET_RAW --cap-add NET_ADMIN netaudit-demo
