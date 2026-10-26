#!/bin/bash
# Kresheen.app's executable: runs the server in a Terminal window (close the window or press Ctrl+C to stop it).
# Terminal is used so the server has a visible window to stop and its address and messages can be read.
here="$(cd "$(dirname "$0")/../Resources/kresheen" && pwd)"
exec open -a Terminal "$here/kresheen"
