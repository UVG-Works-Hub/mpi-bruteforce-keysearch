#!/bin/bash

# =====================================================================
# Script Name: run_mpi_bruteforce_optimized.sh
# Description: Runs the optimized MPI brute-force decryption program
#              for multiple encryption keys and stores the results.
# =====================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Create a directory to store the results
mkdir -p ../test_results/mpi_bruteforce_optimized

# Paths to input files
INPUT_FILE="../tests/b__part/input.txt"
SEARCH_PHRASE_FILE="../tests/b__part/search_phrase.txt"

# Executable for optimized MPI brute-force program
MPI_EXEC="../bin/mpi_bruteforce_optimized"

# Number of processes to use for MPI
NUM_PROCESSES=4

# Array of keys to test
KEYS=("123456" "18014398509481984")

# Check if the optimized executable exists
if [ ! -f "$MPI_EXEC" ]; then
    echo "Error: Executable $MPI_EXEC not found. Please compile the optimized program first." >&2
    exit 1
fi

# Run tests for each key
for KEY in "${KEYS[@]}"; do
    # Define the output file for the current key
    OUTPUT_FILE="../test_results/mpi_bruteforce_optimized/result_key_${KEY}.txt"

    echo "Running optimized MPI brute-force with key $KEY..."

    # Execute the optimized MPI program and redirect output to the output file
    mpirun -np "$NUM_PROCESSES" "$MPI_EXEC" "$INPUT_FILE" "$KEY" "$SEARCH_PHRASE_FILE" > "$OUTPUT_FILE"

    echo "Test with key $KEY completed. Results saved to $OUTPUT_FILE."
done

echo "All optimized MPI brute-force tests completed successfully."
