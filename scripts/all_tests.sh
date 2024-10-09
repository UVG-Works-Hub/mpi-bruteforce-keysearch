#!/bin/bash

# Check if a mode (local or cluster) is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <local|cluster>"
    exit 1
fi

MODE=$1

# Create a directory to store the results
mkdir -p ../test_results/final

# Paths to input files
INPUT_FILE="../tests/b__part/input.txt"
SEARCH_PHRASE_FILE="../tests/b__part/search_phrase.txt"

# Program lists for local and cluster execution
if [ "$MODE" == "local" ]; then
    PROGRAMS=(
        "../bin/mpi_bruteforce_original"
        "../bin/mpi_bruteforce_v1"
        "../bin/naive_sequential"
    )
elif [ "$MODE" == "cluster" ]; then
    PROGRAMS=(
        "../bin/mpi_bruteforce_v2"
    )
else
    echo "Invalid mode. Please specify 'local' or 'cluster'."
    exit 1
fi

# Array of keys to test for specified execution times
# Easy: 123456, Medium: 6e9, Hard: 1.2e10
KEYS=(
    123456             # Easy key (trivial)
    60000000           # Medium key (~6e7)
    120000000          # Hard key (~1.2e8)
    600000000          # Very hard key (~6e8)
    1000000000         # Extremely hard key (~1e9)
)

# CSV output file
CSV_OUTPUT="../test_results/final/times_${MODE}.csv"

# Initialize CSV file with appropriate headers
echo "Program,Key,Plaintext,Search_Phrase,Key_Found,Decrypted_Text,Execution_Time" > $CSV_OUTPUT

# Function to run a test and extract relevant information
run_test() {
    local program=$1
    local key=$2
    local output_file="../test_results/final/$(basename $program)_result_key_${key}.txt"

    # Run the program
    if [[ $program == *mpi_bruteforce_v2* ]]; then
        # MPI v2 program on cluster
        mpirun -np 2 --host lg,sm $program $INPUT_FILE $key $SEARCH_PHRASE_FILE > $output_file
    elif [[ $program == *mpi* ]]; then
        # MPI programs (normal and v1)
        mpirun -np 4 $program $INPUT_FILE $key $SEARCH_PHRASE_FILE > $output_file
    else
        # Sequential program
        $program $INPUT_FILE $key $SEARCH_PHRASE_FILE > $output_file
    fi

    # Extract relevant information from the program output
    plaintext=$(grep "Plaintext:" $output_file | sed 's/Plaintext: -//;s/-//g')
    search_phrase=$(grep "Search phrase:" $output_file | sed 's/Search phrase: -//;s/-//g')
    key_found=$(grep "Key found:" $output_file | awk '{print $3}')
    decrypted_text=$(grep "Decrypted text:" $output_file | sed 's/Decrypted text: -//;s/-//g')
    exec_time=$(grep "Execution time:" $output_file | awk '{print $3}')

    # Save the result to the CSV
    echo "$(basename $program),$key,\"$plaintext\",\"$search_phrase\",$key_found,\"$decrypted_text\",$exec_time" >> $CSV_OUTPUT

    echo "Test with program $(basename $program) and key $key completed. Results saved to $output_file."
}

# Run tests for each program and key
for program in "${PROGRAMS[@]}"; do
    for key in "${KEYS[@]}"; do
        run_test $program $key
    done
done

echo "All tests completed. Results are available in $CSV_OUTPUT."
