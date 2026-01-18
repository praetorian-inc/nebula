#!/usr/bin/env bash
#
# Azure IAM Privilege Escalation Research Orchestrator
#
# Coordinates the full research pipeline:
#   Phase 1: Collect raw data from multiple sources
#   Phase 2: Deduplicate and merge techniques
#   Phase 3: Generate structured markdown files
#   Phase 4: Generate searchable index
#
# Usage: ./scripts/orchestrate.sh [--collectors-only | --synthesis-only | --full]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RAW_DATA_DIR="${PROJECT_ROOT}/raw-data"
INTERMEDIATE_DIR="${PROJECT_ROOT}/intermediate"
TECHNIQUES_DIR="${PROJECT_ROOT}/techniques"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

print_banner() {
    echo "=================================================="
    echo "Azure IAM Privilege Escalation Research Pipeline"
    echo "=================================================="
    echo ""
}

check_dependencies() {
    log_info "Checking dependencies..."

    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "python3 is required but not installed"
        exit 1
    fi

    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
        exit 1
    fi

    # Check required Python packages
    python3 -c "import requests, yaml" 2>/dev/null || {
        log_warning "Missing Python dependencies, installing..."
        pip3 install -r "${SCRIPT_DIR}/collectors/requirements.txt"
    }

    log_success "Dependencies verified"
}

setup_directories() {
    log_info "Setting up directories..."

    mkdir -p "${RAW_DATA_DIR}"
    mkdir -p "${INTERMEDIATE_DIR}"
    mkdir -p "${TECHNIQUES_DIR}/directory-roles"
    mkdir -p "${TECHNIQUES_DIR}/graph-permissions"
    mkdir -p "${TECHNIQUES_DIR}/rbac"
    mkdir -p "${TECHNIQUES_DIR}/cross-domain"

    log_success "Directories ready"
}

run_collectors() {
    log_info "=== PHASE 1: Data Collection ==="
    echo ""

    # Microsoft Official Documentation
    log_info "Running Microsoft documentation collector..."
    python3 "${SCRIPT_DIR}/collectors/microsoft-docs.py" "${RAW_DATA_DIR}" || {
        log_error "Microsoft docs collector failed"
        return 1
    }
    log_success "Microsoft documentation collected"
    echo ""

    # Security Research
    log_info "Running security research collector..."
    python3 "${SCRIPT_DIR}/collectors/security-research.py" "${RAW_DATA_DIR}" || {
        log_error "Security research collector failed"
        return 1
    }
    log_success "Security research collected"
    echo ""

    # MITRE ATT&CK
    log_info "Running MITRE ATT&CK collector..."
    python3 "${SCRIPT_DIR}/collectors/mitre-attack.py" "${RAW_DATA_DIR}" || {
        log_error "MITRE ATT&CK collector failed"
        return 1
    }
    log_success "MITRE ATT&CK data collected"
    echo ""

    log_success "=== PHASE 1 COMPLETE ==="
    echo ""
}

run_synthesis() {
    log_info "=== PHASE 2: Data Synthesis ==="
    echo ""

    # Deduplication
    log_info "Running deduplication..."
    python3 "${SCRIPT_DIR}/synthesis/deduplicate.py" "${RAW_DATA_DIR}" "${INTERMEDIATE_DIR}" || {
        log_error "Deduplication failed"
        return 1
    }
    log_success "Techniques deduplicated"
    echo ""

    # Markdown Generation
    log_info "Generating markdown files..."
    python3 "${SCRIPT_DIR}/synthesis/generate-markdown.py" \
        "${INTERMEDIATE_DIR}/deduplicated-techniques.json" \
        "${TECHNIQUES_DIR}" || {
        log_error "Markdown generation failed"
        return 1
    }
    log_success "Markdown files generated"
    echo ""

    # Index Generation
    log_info "Generating index..."
    python3 "${SCRIPT_DIR}/synthesis/generate-index.py" "${TECHNIQUES_DIR}" || {
        log_error "Index generation failed"
        return 1
    }
    log_success "Index generated"
    echo ""

    log_success "=== PHASE 2 COMPLETE ==="
    echo ""
}

print_summary() {
    log_info "=== RESEARCH PIPELINE SUMMARY ==="
    echo ""

    # Count techniques
    if [ -f "${INTERMEDIATE_DIR}/deduplicated-techniques.json" ]; then
        TECHNIQUE_COUNT=$(python3 -c "import json; data=json.load(open('${INTERMEDIATE_DIR}/deduplicated-techniques.json')); print(data.get('total_techniques', 0))")
        log_info "Total techniques discovered: ${TECHNIQUE_COUNT}"
    fi

    # Count markdown files
    MD_COUNT=$(find "${TECHNIQUES_DIR}" -name "*.md" ! -name "INDEX.md" | wc -l | tr -d ' ')
    log_info "Markdown files generated: ${MD_COUNT}"

    # Count by category
    for category in directory-roles graph-permissions rbac cross-domain; do
        COUNT=$(find "${TECHNIQUES_DIR}/${category}" -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
        log_info "  - ${category}: ${COUNT} techniques"
    done

    echo ""
    log_success "Research pipeline complete!"
    log_info "View results at: ${TECHNIQUES_DIR}/INDEX.md"
}

clean_output() {
    log_warning "Cleaning previous output..."
    rm -rf "${RAW_DATA_DIR}"/*
    rm -rf "${INTERMEDIATE_DIR}"/*
    rm -rf "${TECHNIQUES_DIR}/directory-roles"/*
    rm -rf "${TECHNIQUES_DIR}/graph-permissions"/*
    rm -rf "${TECHNIQUES_DIR}/rbac"/*
    rm -rf "${TECHNIQUES_DIR}/cross-domain"/*
    rm -f "${TECHNIQUES_DIR}/INDEX.md"
    log_success "Previous output cleaned"
    echo ""
}

main() {
    print_banner

    MODE="${1:-full}"

    case "$MODE" in
        --collectors-only)
            log_info "Running collectors only..."
            check_dependencies
            setup_directories
            run_collectors
            ;;
        --synthesis-only)
            log_info "Running synthesis only..."
            check_dependencies
            run_synthesis
            ;;
        --clean)
            clean_output
            ;;
        --full|*)
            log_info "Running full pipeline..."
            check_dependencies
            setup_directories
            run_collectors
            run_synthesis
            print_summary
            ;;
    esac
}

main "$@"
