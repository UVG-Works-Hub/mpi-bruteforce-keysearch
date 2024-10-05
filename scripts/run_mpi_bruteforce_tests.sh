#!/bin/bash

# Create a directory to store the results
mkdir -p ../test_results/mpi_bruteforce

# Paths to input files
INPUT_FILE="../tests/b__part/input.txt"
SEARCH_PHRASE_FILE="../tests/b__part/search_phrase.txt"

# Executable for MPI brute-force program
MPI_EXEC="../bin/mpi_bruteforce"

# Number of processes to use for MPI
NUM_PROCESSES=4

# Array of keys to test
KEYS=("123456" "18014398509481984")

# Run tests for each key
for KEY in "${KEYS[@]}"; do
    # Run the decryption
    OUTPUT_FILE="../test_results/mpi_bruteforce/result_key_${KEY}.txt"
    mpirun -np $NUM_PROCESSES $MPI_EXEC $INPUT_FILE $KEY $SEARCH_PHRASE_FILE > $OUTPUT_FILE

    echo "Test with key $KEY completed. Results saved to $OUTPUT_FILE."
done