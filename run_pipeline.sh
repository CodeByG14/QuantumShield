#!/bin/bash
# QuantumShield Full Pipeline Runner
# Executes: Discovery → Scoring → Dashboard

set -e

echo "=================================================================================="
echo "QuantumShield Week 3 Pipeline"
echo "=================================================================================="
echo ""

echo "Step 1: Discovery (scanning samples/test-repo/)"
echo "---"
uv run discovery/cbom_writer.py
echo ""

echo "Step 2: Scoring (calculating risk scores)"
echo "---"
uv run scoring/qri_engine.py
echo ""

echo "Step 3: Dashboard (displaying results)"
echo "---"
uv run dashboard/view.py
echo ""

echo "=================================================================================="
echo "Pipeline complete!"
echo "Output files:"
echo "  - cbom.json (CBOM with confidence)"
echo "  - scored_output.json (risk scores)"
echo "=================================================================================="
