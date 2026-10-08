#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Cross-platform integration test, Linux side. Env: VARSTO_IT_ROLE=owner|peer,
# S3_ENDPOINT S3_REGION S3_BUCKET S3_KEY S3_SECRET, VAULT_KEY (peer role),
# PUBLIC_IP. The release tarball is expected in /it/varsto.tar.gz.
set -euo pipefail
cd /it && tar xzf varsto.tar.gz && bin="$(ls -d /it/varsto-*/ | head -1)varsto"
export VARSTO_PASSPHRASE=integration-test-passphrase VARSTO_S3_SECRET="$S3_SECRET"
H=/it/home; mkdir -p /it/files
case "$VARSTO_IT_ROLE" in
  owner)
    "$bin" --home $H init --name linux --json > /it/init.json
    "$bin" --home $H storage add-s3 cloud --endpoint "$S3_ENDPOINT" --region "$S3_REGION" --bucket "$S3_BUCKET" --access-key-id "$S3_KEY" --secret-access-key "$S3_SECRET"
    "$bin" --home $H folder add shared /it/files
    head -c 2000000 /dev/urandom > /it/files/from-linux.bin; sha256sum /it/files/from-linux.bin | cut -c1-64 > /it/from-linux.sha
    "$bin" --home $H sync
    "$bin" --home $H p2p enable --port 17893 --public "$PUBLIC_IP:17893"
    python3 -c "import json;print(json.load(open('/it/init.json'))['vault_key'])" > /it/vault-key
    ;;
  peer)
    "$bin" --home $H join --name linux-peer --vault-key "$VAULT_KEY" --storage-name cloud --s3-endpoint "$S3_ENDPOINT" --s3-region "$S3_REGION" --s3-bucket "$S3_BUCKET" --s3-access-key-id "$S3_KEY"
    "$bin" --home $H folder attach shared /it/files
    "$bin" --home $H p2p enable --port 17893 --public "$PUBLIC_IP:17893"
    ;;
esac
nohup "$bin" --home $H service run --port 17890 --interval 60 > /it/service.log 2>&1 &
sleep 5; grep -i "p2p" /it/service.log | head -1
echo "LINUX_READY"
