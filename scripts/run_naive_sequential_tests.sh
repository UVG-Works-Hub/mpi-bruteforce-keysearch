#!/bin/bash

# Create a directory to store the results
mkdir -p test_results/naive_sequential

# Paths to input files
INPUT_FILE="tests/b__part/input.txt"
SEARCH_PHRASE_FILE="tests/b__part/search_phrase.txt"

# Executable for naive sequential program
NAIVE_EXEC="bin/naive_sequential"

# Array of keys to test
# KEYS=("123456" "18014398509481983" "18014398509481984")
KEYS=("123456") # For testing purposes, only use one key.
# The other keys are too large and will take too long to run.

# Run tests for each key
for KEY in "${KEYS[@]}"; do
    # Run the decryption
    OUTPUT_FILE="test_results/naive_sequential/result_key_${KEY}.txt"
    $NAIVE_EXEC $INPUT_FILE $KEY $SEARCH_PHRASE_FILE > $OUTPUT_FILE

    echo "Test with key $KEY completed. Results saved to $OUTPUT_FILE."
done
