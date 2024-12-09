#!/bin/bash

# Parameters
LOOP_COUNT=${1:-5}  # Number of times to run the loop (default: 5)
RUN_TIME=${2:-60}   # Duration for each stress test in seconds (default: 60)

# Array of stress-ng commands to run
COMMANDS=(
    "stress-ng --cpu 2 --timeout ${RUN_TIME}s"
    "stress-ng --vm 1 --vm-bytes 256M --timeout ${RUN_TIME}s"
    "stress-ng --io 2 --timeout ${RUN_TIME}s"
    "stress-ng --hdd 1 --timeout ${RUN_TIME}s"
    "ping 8.8.8.8 -c 100"
)

# Run the commands in a loop
for ((i=1; i<=LOOP_COUNT; i++)); do
    echo "Starting stress-ng loop iteration $i of $LOOP_COUNT..."
    for CMD in "${COMMANDS[@]}"; do
        echo "Running: $CMD"
        eval $CMD
        echo "Command completed."
    done
    echo "Iteration $i completed. Waiting before next iteration..."
    sleep 5  # Optional delay between iterations
done

echo "All stress tests completed."
