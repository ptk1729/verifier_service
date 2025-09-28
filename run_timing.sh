#!/bin/bash

# Script to run 'make run' 5 times and record execution times
# Output file for timing results
OUTPUT_FILE="timing_results.txt"

# Clear the output file if it exists
> "$OUTPUT_FILE"

# Add header to the output file
echo "Make Run Timing Results" >> "$OUTPUT_FILE"
echo "=======================" >> "$OUTPUT_FILE"
echo "Date: $(date)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

echo "Starting timing tests for 'make run'..."
echo "Results will be saved to: $OUTPUT_FILE"
echo ""

# Run make run 5 times
for i in {1..5}; do
    echo "Run $i/5: Starting 'make run'..."
    
    # Record start time
    start_time=$(date +%s.%N)
    
    # Run the command
    make run-all-caddy 
    
    # Record end time
    end_time=$(date +%s.%N)
    
    # Calculate duration
    duration=$(echo "$end_time - $start_time" | bc -l)
    
    # Format the result
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Write to file
    echo "Run $i - $timestamp: ${duration}s" >> "$OUTPUT_FILE"
    
    # Display result
    echo "Run $i completed in: ${duration}s"
    echo ""
done

# Calculate and display summary
echo "Timing Summary:" >> "$OUTPUT_FILE"
echo "==============" >> "$OUTPUT_FILE"

# Extract all durations and calculate statistics
durations=$(grep "Run [0-9]" "$OUTPUT_FILE" | grep -o '[0-9]\+\.[0-9]\+s' | sed 's/s//')

if [ -n "$durations" ]; then
    # Calculate average (requires bc)
    total=0
    count=0
    min_time=999999
    max_time=0
    
    for duration in $durations; do
        total=$(echo "$total + $duration" | bc -l)
        count=$((count + 1))
        
        # Check for min/max
        if (( $(echo "$duration < $min_time" | bc -l) )); then
            min_time=$duration
        fi
        if (( $(echo "$duration > $max_time" | bc -l) )); then
            max_time=$duration
        fi
    done
    
    avg_time=$(echo "scale=3; $total / $count" | bc -l)
    
    echo "Total runs: $count" >> "$OUTPUT_FILE"
    echo "Average time: ${avg_time}s" >> "$OUTPUT_FILE"
    echo "Minimum time: ${min_time}s" >> "$OUTPUT_FILE"
    echo "Maximum time: ${max_time}s" >> "$OUTPUT_FILE"
    
    echo ""
    echo "Summary:"
    echo "--------"
    echo "Total runs: $count"
    echo "Average time: ${avg_time}s"
    echo "Minimum time: ${min_time}s"
    echo "Maximum time: ${max_time}s"
fi

echo ""
echo "All results saved to: $OUTPUT_FILE"
