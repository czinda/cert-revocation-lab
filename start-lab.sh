#!/bin/bash
set -e

echo "========================================================================"
echo "  Event-Driven Certificate Revocation Lab"
echo "  Starting Infrastructure..."
echo "========================================================================"
echo

# Check prerequisites
command -v podman >/dev/null 2>&1 || { echo "Error: podman is required but not installed."; exit 1; }
command -v podman-compose >/dev/null 2>&1 || { echo "Error: podman-compose is required but not installed."; exit 1; }

# Create necessary directories
echo "Creating directory structure..."
mkdir -p data/certs
mkdir -p configs/{rhcs,awx,mock-edr,mock-siem}
mkdir -p ansible/{playbooks,rulebooks,inventory}
mkdir -p notebooks

# Check if volumes need to be cleaned
if [ "$1" == "--clean" ]; then
    echo "Cleaning up existing volumes..."
    podman-compose down -v
    podman volume prune -f
fi

# Add DNS entries to /etc/hosts (requires sudo)
echo
echo "Adding DNS entries to /etc/hosts (requires sudo)..."
if ! grep -q "cert-lab.local" /etc/hosts; then
    sudo tee -a /etc/hosts > /dev/null <<EOF

# Cert Revocation Lab
172.20.0.10 ipa.cert-lab.local ipa
172.20.0.11 ca.cert-lab.local ca
172.20.0.20 postgres.cert-lab.local postgres
172.20.0.21 redis.cert-lab.local redis
172.20.0.22 awx.cert-lab.local awx
172.20.0.23 awx-task.cert-lab.local awx-task
172.20.0.30 zookeeper.cert-lab.local zookeeper
172.20.0.31 kafka.cert-lab.local kafka
172.20.0.40 eda.cert-lab.local eda
172.20.0.50 edr.cert-lab.local edr
172.20.0.51 siem.cert-lab.local siem
172.20.0.60 jupyter.cert-lab.local jupyter
172.20.0.100 device01.cert-lab.local device01
EOF
    echo "✓ DNS entries added"
else
    echo "✓ DNS entries already present"
fi

# Start core infrastructure
echo
echo "========================================================================"
echo "Phase 1: Starting Core Infrastructure (PostgreSQL, Redis, Zookeeper)"
echo "========================================================================"
podman-compose up -d postgres redis zookeeper
echo "Waiting for database services to initialize (30 seconds)..."
sleep 30

# Start FreeIPA
echo
echo "========================================================================"
echo "Phase 2: Starting FreeIPA (This may take 10-15 minutes first run)"
echo "========================================================================"
podman-compose up -d freeipa
echo "FreeIPA is initializing in the background..."
echo "You can monitor progress: podman logs -f ipa-server"
echo "Waiting 120 seconds before proceeding..."
sleep 120

# Start Kafka
echo
echo "========================================================================"
echo "Phase 3: Starting Event Bus (Kafka)"
echo "========================================================================"
podman-compose up -d kafka
echo "Waiting for Kafka to be ready (30 seconds)..."
sleep 30

# Create Kafka topic
echo "Creating security-events topic..."
podman exec kafka kafka-topics --create \
    --bootstrap-server localhost:9092 \
    --topic security-events \
    --partitions 3 \
    --replication-factor 1 \
    --if-not-exists 2>/dev/null || echo "Topic already exists"

# Start mock security tools
echo
echo "========================================================================"
echo "Phase 4: Starting Mock EDR and SIEM"
echo "========================================================================"
podman-compose up -d mock-edr mock-siem
sleep 10

# Start Jupyter
echo
echo "========================================================================"
echo "Phase 5: Starting Jupyter Lab"
echo "========================================================================"
podman-compose up -d jupyter
sleep 10

# Display status
echo
echo "========================================================================"
echo "  Lab Environment Started Successfully!"
echo "========================================================================"
echo
echo "Service URLs:"
echo "  FreeIPA UI:      https://192.168.1.121:8443/ipa/ui"
echo "  AWX UI:          http://192.168.1.121:8080"
echo "  Jupyter Lab:     http://192.168.1.121:8888"
echo "  Mock EDR API:    http://192.168.1.121:8082"
echo "  Mock SIEM API:   http://192.168.1.121:8083"
echo
echo "Default Credentials:"
echo "  IPA Admin:       admin / RedHat123!"
echo "  AWX Admin:       admin / RedHat123!"
echo "  Jupyter Token:   RedHat123"
echo
echo "Testing:"
echo "  Run test:        ./test-revocation.sh"
echo "  View logs:       podman-compose logs -f <service-name>"
echo "========================================================================"
