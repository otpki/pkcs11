#!/bin/sh
# The package files, including package-hooks, have already been removed.
# Do not remove configs, the service account, audit logs, keys, or vendor files.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
