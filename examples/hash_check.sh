#!/bin/bash

# Function to calculate hash of JSON report in compact form
calculate_json_hash() {
    local json_file="$1"
    
    if [ ! -f "$json_file" ]; then
        echo "Error: File $json_file does not exist" >&2
        return 1
    fi
    
    # Extract just the report section and compact it, then calculate hash
    jq -c '.report' "$json_file" | tr -d ' \t\n\r' | sha256sum | cut -d' ' -f1
}

# Function to verify hash against the one stored in metadata
verify_report_hash() {
    local json_file="$1"
    
    if [ ! -f "$json_file" ]; then
        echo "Error: File $json_file does not exist" >&2
        return 1
    fi
    
    # Extract stored hash from metadata
    local stored_hash=$(jq -r '.metadata.report_sha256' "$json_file")
    
    if [ "$stored_hash" = "null" ] || [ -z "$stored_hash" ]; then
        echo "Error: No report_sha256 found in metadata" >&2
        return 1
    fi
    
    # Calculate current hash
    local calculated_hash=$(calculate_json_hash "$json_file")
    
    echo "Stored hash:     $stored_hash"
    echo "Calculated hash: $calculated_hash"
    
    if [ "$stored_hash" = "$calculated_hash" ]; then
        echo "✅ Hash verification PASSED"
        return 0
    else
        echo "❌ Hash verification FAILED"
        return 1
    fi
}

# Function to just get the compact JSON (useful for debugging)
get_compact_report() {
    local json_file="$1"
    
    if [ ! -f "$json_file" ]; then
        echo "Error: File $json_file does not exist" >&2
        return 1
    fi
    
    jq -c '.report' "$json_file" | tr -d ' \t\n\r'
}

# Main script logic
if [ $# -eq 0 ]; then
    echo "Usage: $0 <command> <json_file> [expected_hash]"
    echo ""
    echo "Commands:"
    echo "  hash <json_file>                    - Calculate hash of report section"
    echo "  verify <json_file>                  - Verify hash against stored metadata"
    echo "  compact <json_file>                 - Show compact JSON (for debugging)"
    echo "  compare <json_file> <expected_hash> - Compare calculated hash with expected"
    echo ""
    echo "Examples:"
    echo "  $0 hash /tmp/report_20240804.json"
    echo "  $0 verify /tmp/report_20240804.json"
    echo "  $0 compare /tmp/report_20240804.json abc123def456..."
    exit 1
fi

command="$1"
json_file="$2"
expected_hash="$3"

case "$command" in
    "hash")
        calculate_json_hash "$json_file"
        ;;
    "verify")
        verify_report_hash "$json_file"
        ;;
    "compact")
        get_compact_report "$json_file"
        ;;
    "compare")
        if [ -z "$expected_hash" ]; then
            echo "Error: Expected hash is required for compare command" >&2
            exit 1
        fi
        calculated_hash=$(calculate_json_hash "$json_file")
        echo "Expected hash:   $expected_hash"
        echo "Calculated hash: $calculated_hash"
        if [ "$expected_hash" = "$calculated_hash" ]; then
            echo "✅ Hash comparison PASSED"
            exit 0
        else
            echo "❌ Hash comparison FAILED"
            exit 1
        fi
        ;;
    *)
        echo "Error: Unknown command '$command'" >&2
        echo "Use '$0' without arguments to see usage." >&2
        exit 1
        ;;
esac