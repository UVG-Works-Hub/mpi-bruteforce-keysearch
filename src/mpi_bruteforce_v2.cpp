/**
 * @file mpi_bruteforce_v2.cpp
 * @brief MPI and OpenMP program to encrypt and brute-force decrypt a plaintext using OpenSSL's DES.
 *
 * This program uses MPI for distributed memory parallelism and OpenMP for shared memory parallelism.
 * It includes inter-process communication to allow early exit when a key is found.
 *
 * @note Compile using Open MPI, OpenMP, and OpenSSL libraries:
 * mpic++ -fopenmp -O3 -march=native -o mpi_bruteforce_v2 mpi_bruteforce_v2.cpp -lssl -lcrypto
 *
 * Example usage:
 * mpirun -np 4 ./mpi_bruteforce_v2 plaintext.txt 123456 search_phrase.txt
 *
 * @date October 2024
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/des.h>
#include <mpi.h>
#include <omp.h>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <locale>

#define DEBUG 0  // Set to 1 to enable debug messages

/**
 * @brief Trims leading and trailing whitespace from both ends of a string (in place).
 *
 * @param s The string to be trimmed.
 */
static inline void trim(std::string &s) {
    // Trim leading whitespace
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    // Trim trailing whitespace
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

/**
 * @brief Encrypts the plaintext using DES with the specified key.
 *
 * @param key The 8-byte DES key.
 * @param plaintext The input data to encrypt.
 * @param ciphertext The buffer to store encrypted data.
 * @param len Length of the plaintext.
 */
void encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned char* ciphertext, int len) {
    DES_cblock keyBlock;
    DES_key_schedule keySchedule;

    memcpy(keyBlock, key, 8);

    // Suppress deprecated warnings for OpenSSL DES functions
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Set the key parity bits
    DES_set_odd_parity(&keyBlock);

    // Use DES_set_key_unchecked to set the key schedule
    DES_set_key_unchecked(&keyBlock, &keySchedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(plaintext + i), (DES_cblock*)(ciphertext + i), &keySchedule, DES_ENCRYPT);
    }

#pragma GCC diagnostic pop  // Restore the previous warning settings
}

/**
 * @brief Decrypts the ciphertext using DES with the specified key.
 *
 * @param key The 8-byte DES key.
 * @param ciphertext The encrypted data.
 * @param plaintext The buffer to store decrypted data.
 * @param len Length of the ciphertext.
 */
void decrypt(const unsigned char* key, const unsigned char* ciphertext, unsigned char* plaintext, int len) {
    DES_cblock keyBlock;
    DES_key_schedule keySchedule;

    memcpy(keyBlock, key, 8);

    // Suppress deprecated warnings for OpenSSL DES functions
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Set the key parity bits
    DES_set_odd_parity(&keyBlock);

    // Use DES_set_key_unchecked to set the key schedule
    DES_set_key_unchecked(&keyBlock, &keySchedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(ciphertext + i), (DES_cblock*)(plaintext + i), &keySchedule, DES_DECRYPT);
    }

#pragma GCC diagnostic pop  // Restore the previous warning settings
}

/**
 * @brief Converts a 64-bit integer to an 8-byte key.
 *
 * @param key The 64-bit integer key.
 * @param keyArray The buffer to store the converted 8-byte key.
 */
void longToKey(uint64_t key, unsigned char* keyArray) {
    for (int i = 0; i < 8; ++i) {
        keyArray[7 - i] = (key >> (i * 8)) & 0xFF;
    }
}

/**
 * @brief Main function that orchestrates the MPI and OpenMP brute-force key search.
 */
int main(int argc, char* argv[]) {
    // Initialize MPI environment
    MPI_Init(&argc, &argv);

    int numProcesses, processId;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Comm_size(comm, &numProcesses);
    MPI_Comm_rank(comm, &processId);

    std::string plaintext;
    std::string searchPhrase;
    uint64_t encryptionKey;

    // Process 0 reads the input files and broadcasts the data
    if (processId == 0) {
        if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " <input_file> <encryption_key> <search_phrase_file>" << std::endl;
            MPI_Abort(comm, 1);
        }

        // Load plaintext from the file, skipping empty lines
        std::ifstream inputFile(argv[1]);
        if (!inputFile) {
            std::cerr << "Failed to open input file." << std::endl;
            MPI_Abort(comm, 1);
        }

        std::string line;
        bool firstLine = true; // Flag to handle spacing correctly
        while (std::getline(inputFile, line)) {
            trim(line);
            if (!line.empty()) {
                if (!firstLine) {
                    plaintext += ' ';  // Add a space between lines
                }
                plaintext += line;
                firstLine = false;
            }
        }
        inputFile.close();

        // Load the search phrase from the file, skipping empty lines
        std::ifstream searchPhraseFile(argv[3]);
        if (!searchPhraseFile) {
            std::cerr << "Failed to open search phrase file." << std::endl;
            MPI_Abort(comm, 1);
        }

        std::string searchLine;
        firstLine = true; // Reset flag for search phrase
        while (std::getline(searchPhraseFile, searchLine)) {
            trim(searchLine);
            if (!searchLine.empty()) {
                if (!firstLine) {
                    searchPhrase += ' ';  // Add a space between lines
                }
                searchPhrase += searchLine;
                firstLine = false;
            }
        }
        searchPhraseFile.close();

        // Convert encryption key to uint64_t
        try {
            encryptionKey = std::stoull(argv[2]);
        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid encryption key format." << std::endl;
            MPI_Abort(comm, 1);
        }

        // Print plaintext and search phrase
        std::cout << "Plaintext: -" << plaintext << "-" << std::endl;
        std::cout << "Search phrase: -" << searchPhrase << "-" << std::endl;
        std::cout << "Encryption key: " << encryptionKey << std::endl;
    }

    // Broadcast encryption key
    MPI_Bcast(&encryptionKey, 1, MPI_UINT64_T, 0, comm);

    // Broadcast plaintext
    int plaintextLength;
    if (processId == 0) {
        plaintextLength = plaintext.size();
    }
    MPI_Bcast(&plaintextLength, 1, MPI_INT, 0, comm);

    if (processId != 0) {
        plaintext.resize(plaintextLength);
    }
    MPI_Bcast(&plaintext[0], plaintextLength, MPI_CHAR, 0, comm);

    // Broadcast search phrase
    int searchPhraseLength;
    if (processId == 0) {
        searchPhraseLength = searchPhrase.size();
    }
    MPI_Bcast(&searchPhraseLength, 1, MPI_INT, 0, comm);

    if (processId != 0) {
        searchPhrase.resize(searchPhraseLength);
    }
    MPI_Bcast(&searchPhrase[0], searchPhraseLength, MPI_CHAR, 0, comm);

    // Ensure the plaintext length is a multiple of 8
    int paddedLength = ((plaintext.size() + 7) / 8) * 8;
    unsigned char* plaintextBuffer = new unsigned char[paddedLength];
    memset(plaintextBuffer, 0, paddedLength);
    memcpy(plaintextBuffer, plaintext.c_str(), plaintext.size());

    // Convert encryption key to 8-byte DES key
    unsigned char keyArray[8];
    longToKey(encryptionKey, keyArray);

    // Encrypt the plaintext
    unsigned char* ciphertext = new unsigned char[paddedLength];
    encrypt(keyArray, plaintextBuffer, ciphertext, paddedLength);

    // Define key space and range for each process
    uint64_t upperBound = (1ULL << 56);  // 2^56 keys for DES
    uint64_t keysPerProcess = upperBound / numProcesses;
    uint64_t lowerBound = keysPerProcess * processId;
    uint64_t upperBoundLocal = (processId == numProcesses - 1) ? upperBound : lowerBound + keysPerProcess;

    uint64_t foundKey = 0;
    bool keyFound = false;
    uint64_t globalFoundKey = 0;
    bool globalKeyFound = false;

    // Start timing
    MPI_Barrier(comm);  // Ensure all processes start at the same time
    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "Process " << processId << " searching keys " << lowerBound << " to " << upperBoundLocal - 1 << std::endl;
    // Set the number of threads to 4 for OpenMP
    omp_set_num_threads(4);

    // Define chunk size
    uint64_t chunkSize = 1000000; // Adjust as needed
    uint64_t currentKey = lowerBound;

    while (currentKey < upperBoundLocal && !globalKeyFound) {
        uint64_t chunkEnd = std::min(currentKey + chunkSize, upperBoundLocal);

        // Brute-force key search with OpenMP
#pragma omp parallel shared(foundKey, keyFound)
        {
            // Each thread has its own local variables
            unsigned char localKeyArray[8];
            unsigned char localDecrypted[paddedLength + 1];

            // Loop over keys assigned to this chunk
#pragma omp for schedule(dynamic, 1024)
            for (uint64_t key = currentKey; key < chunkEnd; ++key) {
                // Early exit if key is found
                if (keyFound) {
                    continue;
                }

                // Convert key to key array
                longToKey(key, localKeyArray);

                // Decrypt the ciphertext
                decrypt(localKeyArray, ciphertext, localDecrypted, paddedLength);
                localDecrypted[paddedLength] = '\0';  // Null-terminate

                // Check if decrypted text contains the search phrase
                if (strstr(reinterpret_cast<char*>(localDecrypted), searchPhrase.c_str()) != nullptr) {
                    // Critical section to update shared variables
#pragma omp critical
                    {
                        if (!keyFound) {
                            foundKey = key;
                            keyFound = true;
                        }
                    }
                }
            }
        }  // End of OpenMP parallel region

        // Check if keyFound
        if (keyFound) {
            // Send foundKey to all other processes
            for (int i = 0; i < numProcesses; ++i) {
                if (i != processId) {
                    MPI_Send(&foundKey, 1, MPI_UINT64_T, i, 0, comm);
                }
            }
            globalFoundKey = foundKey;
            globalKeyFound = true;
        } else {
            // Non-blocking probe for messages from other processes
            int flag = 0;
            MPI_Status status;
            while (true) {
                MPI_Iprobe(MPI_ANY_SOURCE, 0, comm, &flag, &status);
                if (flag) {
                    uint64_t receivedKey;
                    MPI_Recv(&receivedKey, 1, MPI_UINT64_T, status.MPI_SOURCE, 0, comm, MPI_STATUS_IGNORE);
                    globalFoundKey = receivedKey;
                    globalKeyFound = true;
                    keyFound = true;
                    foundKey = receivedKey;
                } else {
                    break;
                }
            }
        }

        // Update currentKey
        currentKey = chunkEnd;
    }

    // End timing
    MPI_Barrier(comm);  // Ensure all processes have finished
    auto end = std::chrono::high_resolution_clock::now();

    // Process 0 handles the output
    if (processId == 0) {
        if (globalFoundKey != 0) {
            unsigned char decryptedText[paddedLength + 1];
            unsigned char foundKeyArray[8];
            longToKey(globalFoundKey, foundKeyArray);
            decrypt(foundKeyArray, ciphertext, decryptedText, paddedLength);
            decryptedText[paddedLength] = '\0';
            std::cout << "Key found: " << globalFoundKey << "\nDecrypted text: -" << decryptedText << "-" << std::endl;
        } else {
            std::cout << "Key not found in the specified range." << std::endl;
        }

        std::chrono::duration<double> duration = end - start;
        std::cout << "Execution time: " << duration.count() << " seconds" << std::endl;
    }

    // Clean up
    delete[] plaintextBuffer;
    delete[] ciphertext;

    MPI_Finalize();
    return 0;
}
