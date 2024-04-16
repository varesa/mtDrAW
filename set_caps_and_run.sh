#!/bin/sh
set -euo pipefail

echo "Adding CAP_NET_ADMIN to '$1'"
sudo setcap cap_net_admin=ep "$1"
echo "Executing '$1'"
"$@"

