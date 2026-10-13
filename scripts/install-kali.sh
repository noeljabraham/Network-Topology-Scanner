#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sudo apt-get update
sudo apt-get install -y nmap python3-venv iproute2 iputils-ping
python3 -m venv "$project_dir/.venv"
"$project_dir/.venv/bin/pip" install -r "$project_dir/requirements.txt"
echo "Installed. Run: $project_dir/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000"
