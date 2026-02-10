# Event-Driven Certificate Revocation Lab

Comprehensive lab environment demonstrating automated certificate lifecycle management in Zero Trust Architecture using Red Hat products.

## Architecture

- **FreeIPA (IdM)** - Identity Management & Certificate Store
- **RHCS (Dogtag PKI)** - Certificate Authority
- **Ansible AWX** - Automation Platform
- **Event-Driven Ansible** - Real-time Event Processing
- **Kafka** - Event Streaming Bus
- **Mock EDR/SIEM** - Security Event Generators

## Quick Start
```bash
# Clone or extract to your server
cd ~/cert-revocation-lab

# Make scripts executable
chmod +x *.sh

# Start the lab (first run takes 10-15 minutes)
./start-lab.sh

# Wait for all services to be ready
# Check status at: http://192.168.1.121:8888 (Jupyter)

# Run a test scenario
./test-revocation.sh

# Stop the lab
./stop-lab.sh
```

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| FreeIPA Web UI | https://192.168.1.121:8443/ipa/ui | admin / RedHat123! |
| RHCS CA | https://192.168.1.121:8443/ca/services | admin / RedHat123! |
| AWX Web UI | http://192.168.1.121:8080 | admin / RedHat123! |
| Jupyter Lab | http://192.168.1.121:8888 | Token: RedHat123 |
| Mock EDR API | http://192.168.1.121:8082 | - |
| Mock SIEM API | http://192.168.1.121:8083 | - |
| EDA Webhook | http://192.168.1.121:5000 | - |

## Performance Metrics

- Detection to Revocation: < 60 seconds
- Manual Baseline: 4-8 hours
- Time Reduction: 99.8%
- Zero Human Intervention

## Author

**czinda** - Red Hat Senior Technical Product Manager  
Focus: PKI, Identity Management, Zero Trust Architecture

## License

Educational/Demo Use Only
