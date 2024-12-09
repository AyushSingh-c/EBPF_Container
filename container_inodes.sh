#!/bin/bash

# List all running containers
containers=$(docker ps -q)

# Check each container
for container in $containers; do
    echo "Container ID: $container"
    pid=$(docker inspect -f '{{.State.Pid}}' $container)
    echo "PID: $pid"
    echo "Namespace inodes:"
    ls -l /proc/$pid/ns
    echo "-------------------------"
done
