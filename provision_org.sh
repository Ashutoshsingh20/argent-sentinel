#!/usr/bin/env bash
set -euo pipefail

# Provisioning script for spawning new isolated organizations

ORG_ID="${1:?Usage: ./provision_org.sh <org-id> <port>}"
PORT="${2:?Usage: ./provision_org.sh <org-id> <port>}"

echo "=================================================="
echo "Provisioning isolated environments for Org: $ORG_ID"
echo "=================================================="

# Create isolated volume mounts
mkdir -p "data/$ORG_ID" "models/$ORG_ID" "policies/$ORG_ID"

# Copy the default zero-trust safety rules template
if [ -f "adaptive_zta/policies/rules.yaml" ]; then
  cp "adaptive_zta/policies/rules.yaml" "policies/$ORG_ID/rules.yaml"
  echo "✓ Copied default policy engine rules to policies/$ORG_ID/rules.yaml"
elif [ -f "policies/rules.yaml" ]; then
  cp "policies/rules.yaml" "policies/$ORG_ID/rules.yaml"
  echo "✓ Copied default policy engine rules to policies/$ORG_ID/rules.yaml"
else
  echo "⚠ Warning: Default rules.yaml not found. Skipping copy."
fi

# Generate unique tenant env configuration with cryptographically secure secret
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "fallback-$(date +%s | sha256sum | cut -d' ' -f1)")

mkdir -p tenants
cat > "tenants/$ORG_ID.env" << EOF
TENANT_ID=$ORG_ID
APP_PORT=8000
JWT_SECRET=$JWT_SECRET
DB_URL=sqlite:///app/data/argent.db
MODEL_PATH=/app/models/tabnet_weights.pt
TABNET_ACTIVATION_THRESHOLD=3000
TENANT_ISOLATION=1
REDIS_ENABLED=0
CLOUD_ACTIONS_ENABLED=0
LOG_FORMAT=json
LOG_LEVEL=INFO
AUTH_ALLOW_INSECURE_DEV=1
EOF

echo "✓ Generated tenants/$ORG_ID.env configuration profile"
echo "=================================================="
echo "Done! To register this org in Docker Orchestrator:"
echo "1. Append a new service block in docker-compose.yml:"
echo "   $ORG_ID:"
echo "     build: ."
echo "     env_file: tenants/$ORG_ID.env"
echo "     ports:"
echo "       - \"$PORT:8000\""
echo "     volumes:"
echo "       - ./data/$ORG_ID:/app/data"
echo "       - ./models/$ORG_ID:/app/models"
echo "       - ./policies/$ORG_ID:/app/policies"
echo "     restart: unless-stopped"
echo "     healthcheck:"
echo "       test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:8000/healthz\"]"
echo "       interval: 30s"
echo "       timeout: 10s"
echo "       retries: 3"
echo "       start_period: 15s"
echo ""
echo "2. Add \"$ORG_ID\" upstream target and map it in nginx.conf"
echo "3. Run 'docker compose up -d --build' to apply changes"
echo "=================================================="
