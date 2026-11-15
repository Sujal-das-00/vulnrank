#!/usr/bin/env bash
# usage: scripts/devserver.sh start|stop   (pid file based; no pkill)
cd "$(dirname "$0")/.."
PID=.devserver.pid
case "$1" in
  stop) [ -f $PID ] && kill "$(cat $PID)" 2>/dev/null; rm -f $PID ;;
  start) nohup .venv/bin/uvicorn app.main:app --port "${PORT:-8765}" > "${LOG:-/dev/null}" 2>&1 & echo $! > $PID ;;
esac
