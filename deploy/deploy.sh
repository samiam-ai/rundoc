#!/usr/bin/env bash
# RunDoc — deploy script
# Usage: bash deploy/deploy.sh
# Run from the repo root on your local machine.

set -e

SERVER="sam@192.168.1.128"
REMOTE_DIR="/opt/rundoc"

echo "==> Syncing files to $SERVER:$REMOTE_DIR"
ssh $SERVER "mkdir -p $REMOTE_DIR/backend $REMOTE_DIR/frontend"

scp backend/main.py          $SERVER:$REMOTE_DIR/backend/main.py
scp backend/requirements.txt $SERVER:$REMOTE_DIR/backend/requirements.txt
scp -r frontend/             $SERVER:$REMOTE_DIR/frontend/

echo "==> Installing Python dependencies"
ssh $SERVER "
  cd $REMOTE_DIR
  python3 -m venv venv
  venv/bin/pip install --quiet --upgrade pip
  venv/bin/pip install --quiet -r backend/requirements.txt
"

echo "==> Restarting service"
ssh $SERVER "sudo systemctl restart rundoc && sudo systemctl status rundoc --no-pager"

echo "==> Done. RunDoc is live at http://192.168.1.128:8000"
