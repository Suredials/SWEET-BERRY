#!/bin/sh
# Save the current evidence and restart collectors, keeping target state.
set -eu
sudo systemctl start sweetberry-new-test.service
echo 'Captura guardada; nueva prueba lista. Los objetivos se conservan.'
