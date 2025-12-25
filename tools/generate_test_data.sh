#!/bin/bash
# Comprehensive Test Data Generation Script for Cerberus SIEM
# This script seeds the database and executes attack scenarios

set -e

echo "========================================"
echo "Cerberus Test Data Generation"
echo "========================================"
echo ""

# Check if Cerberus API is running
echo "[1/5] Checking if Cerberus API is running..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/health || echo "000")

if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Cerberus API is not running on http://localhost:8080"
    echo "Please start the Cerberus API first: ./cerberus"
    exit 1
fi
echo "✓ API is running"
echo ""

# Step 1: Seed rules and actions
echo "[2/5] Seeding detection rules, correlation rules, and actions..."
./bin/seed -rules -actions -clear
echo ""

# Step 2: Wait for rules to be loaded
echo "[3/5] Waiting 5 seconds for rules to be loaded..."
sleep 5
echo ""

# Step 3: Execute generic scenarios
echo "[4/5] Executing generic attack scenarios..."
echo ""

scenarios=(
    "brute_force"
    "port_scan"
    "data_exfiltration"
    "lateral_movement"
)

for scenario in "${scenarios[@]}"; do
    echo "  - Executing $scenario scenario..."
    ./bin/scenario -scenario "tools/scenarios/definitions/${scenario}.yaml"
    echo ""
done

# Step 4: Execute Windows-specific scenarios
echo "[5/5] Executing Windows-specific attack scenarios..."
echo ""

windows_scenarios=(
    "windows_brute_force"
    "windows_account_compromise"
    "windows_privilege_escalation"
    "windows_audit_tampering"
    "windows_persistence"
    "windows_mass_deletion"
    "windows_lateral_movement"
    "windows_system_compromise"
)

for scenario in "${windows_scenarios[@]}"; do
    echo "  - Executing $scenario scenario..."
    ./bin/scenario -scenario "tools/scenarios/definitions/${scenario}.yaml"
    echo ""
done

echo "========================================"
echo "✅ Test Data Generation Complete!"
echo "========================================"
echo ""
echo "You can now view the generated data:"
echo "  - Events: http://localhost:8080/events"
echo "  - Alerts: http://localhost:8080/alerts"
echo "  - Dashboard: http://localhost:8080/"
echo ""
