/**
 * @file mpi_bruteforce_reoptimized.cpp
 * @brief MPI and OpenMP program to encrypt and brute-force decrypt a plaintext using OpenSSL's DES.
 *
 * This program uses MPI for distributed memory parallelism and OpenMP for shared memory parallelism.
 * It includes inter-process communication to allow early exit when a key is found.
 *
 * @note Compile using Open MPI, OpenMP, and OpenSSL libraries:
 * mpic++ -fopenmp -O3 -march=native -o mpi_bruteforce_reoptimized mpi_bruteforce_reoptimized.cpp -lssl -lcrypto
 *
 * Example usage:
 * mpirun -np 4 ./mpi_bruteforce_reoptimized plaintext.txt 123456 search_phrase.txt
 *
 * @date October 2024
 */

#include <mpi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <immintrin.h>
#include <memory>
#include <cstring>
#include <openssl/des.h>

// Abstract base class for encryption/decryption algorithms
class CryptoAlgorithm {
public:
    virtual ~CryptoAlgorithm() = default;
    virtual void encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned char* ciphertext, int len) const = 0;
    virtual void decrypt(const unsigned char* key, const unsigned char* ciphertext, unsigned char* plaintext, int len) const = 0;
};

// DES implementation
class DESAlgorithm : public CryptoAlgorithm {
public:
    /**
    * @brief Encrypts the plaintext using DES with the specified key.
    *
    * @param key The 8-byte DES key.
    * @param plaintext The input data to encrypt.
    * @param ciphertext The buffer to store encrypted data.
    * @param len Length of the plaintext.
    */
    void encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned char* ciphertext, int len) const override {
        DES_cblock keyBlock;
        DES_key_schedule keySchedule;

        memcpy(keyBlock, key, 8);
        DES_set_odd_parity(&keyBlock);
        DES_set_key_checked(&keyBlock, &keySchedule);

        for (int i = 0; i < len; i += 8) {
            DES_ecb_encrypt((const_DES_cblock*)(plaintext + i), (DES_cblock*)(ciphertext + i), &keySchedule, DES_ENCRYPT);
        }
    }
    /**
     * @brief Decrypts the ciphertext using DES with the specified key.
     *
     * @param key The 8-byte DES key.
     * @param ciphertext The encrypted data.
     * @param plaintext The buffer to store decrypted data.
     * @param len Length of the ciphertext.
     */
    void decrypt(const unsigned char* key, const unsigned char* ciphertext, unsigned char* plaintext, int len) const override {
        DES_cblock keyBlock;
        DES_key_schedule keySchedule;

        memcpy(keyBlock, key, 8);
        DES_set_odd_parity(&keyBlock);
        DES_set_key_checked(&keyBlock, &keySchedule);

        for (int i = 0; i < len; i += 8) {
            DES_ecb_encrypt((const_DES_cblock*)(ciphertext + i), (DES_cblock*)(plaintext + i), &keySchedule, DES_DECRYPT);
        }
    }
};

// Template function for key conversion
template<typename KeyType>
void keyToArray(KeyType key, unsigned char* keyArray, size_t keySize) {
    for (size_t i = 0; i < keySize; ++i) {
        keyArray[keySize - 1 - i] = (key >> (i * 8)) & 0xFF;
    }
}

// Template class for parallel key search
template<typename KeyType>
class ParallelKeySearch {
private:
    std::unique_ptr<CryptoAlgorithm> cryptoAlgo;
    const unsigned char* ciphertext;
    int ciphertextLen;
    const std::string& searchPhrase;
    size_t keySize;

public:
    ParallelKeySearch(std::unique_ptr<CryptoAlgorithm> algo, const unsigned char* ct, int ctLen, const std::string& phrase, size_t kSize)
        : cryptoAlgo(std::move(algo)), ciphertext(ct), ciphertextLen(ctLen), searchPhrase(phrase), keySize(kSize) {}

    bool tryKey(KeyType key) const {
        std::vector<unsigned char> keyArray(keySize);
        keyToArray(key, keyArray.data(), keySize);

        std::vector<unsigned char> decrypted(ciphertextLen + 1);
        cryptoAlgo->decrypt(keyArray.data(), ciphertext, decrypted.data(), ciphertextLen);
        decrypted[ciphertextLen] = '\0';

        return strstr(reinterpret_cast<char*>(decrypted.data()), searchPhrase.c_str()) != nullptr;
    }

    KeyType searchRange(KeyType start, KeyType end) const {
        const int vectorSize = 256 / (8 * sizeof(KeyType));
        alignas(32) KeyType keys[vectorSize];

        for (KeyType key = start; key < end; key += vectorSize) {
            for (int i = 0; i < vectorSize; ++i) {
                keys[i] = key + i;
            }

            __m256i vectorKeys = _mm256_load_si256(reinterpret_cast<__m256i*>(keys));
            __m256i result = _mm256_setzero_si256();

            for (int i = 0; i < vectorSize; ++i) {
                if (tryKey(keys[i])) {
                    return keys[i];
                }
            }
        }

        return 0;
    }
};

/**
 * @brief Trims leading and trailing whitespace from both ends of a string (in place).
 *
 * @param s The string to be trimmed.
 */
static inline void trim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc != 4) {
        if (rank == 0) {
            std::cerr << "Usage: " << argv[0] << " <input_file> <encryption_key> <search_phrase_file>" << std::endl;
        }
        MPI_Finalize();
        return 1;
    }

    std::string plaintext;
    std::string searchPhrase;
    uint64_t encryptionKey;

    if (rank == 0) {
        // Read plaintext
        std::ifstream inputFile(argv[1]);
        if (!inputFile) {
            std::cerr << "Failed to open input file." << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        std::string line;
        while (std::getline(inputFile, line)) {
            trim(line);
            if (!line.empty()) {
                plaintext += line + " ";
            }
        }
        trim(plaintext);

        // Read search phrase
        std::ifstream searchPhraseFile(argv[3]);
        if (!searchPhraseFile) {
            std::cerr << "Failed to open search phrase file." << std::endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        while (std::getline(searchPhraseFile, line)) {
            trim(line);
            if (!line.empty()) {
                searchPhrase += line + " ";
            }
        }
        trim(searchPhrase);

        // Convert encryption key
        encryptionKey = std::stoull(argv[2]);

        std::cout << "Plaintext: " << plaintext << std::endl;
        std::cout << "Search phrase: " << searchPhrase << std::endl;
    }

    // Broadcast data to all processes
    int plaintextLength = plaintext.length();
    MPI_Bcast(&plaintextLength, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) plaintext.resize(plaintextLength);
    MPI_Bcast(&plaintext[0], plaintextLength, MPI_CHAR, 0, MPI_COMM_WORLD);

    int searchPhraseLength = searchPhrase.length();
    MPI_Bcast(&searchPhraseLength, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (rank != 0) searchPhrase.resize(searchPhraseLength);
    MPI_Bcast(&searchPhrase[0], searchPhraseLength, MPI_CHAR, 0, MPI_COMM_WORLD);

    MPI_Bcast(&encryptionKey, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

    // Pad plaintext to multiple of 8 bytes
    int paddedLength = ((plaintextLength + 7) / 8) * 8;
    std::vector<unsigned char> plaintextBuffer(paddedLength, 0);
    std::copy(plaintext.begin(), plaintext.end(), plaintextBuffer.begin());

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext(paddedLength);
    std::unique_ptr<CryptoAlgorithm> encryptionAlgo = std::make_unique<DESAlgorithm>();
    unsigned char keyArray[8];
    keyToArray(encryptionKey, keyArray, 8);
    encryptionAlgo->encrypt(keyArray, plaintextBuffer.data(), ciphertext.data(), paddedLength);

    // Set up parallel key search
    ParallelKeySearch<uint64_t> keySearch(std::move(encryptionAlgo), ciphertext.data(), paddedLength, searchPhrase, 8);

    uint64_t globalLowerBound = 0;
    uint64_t globalUpperBound = (1ULL << 56) - 1;  // Full 56-bit DES key space
    uint64_t chunkSize = 1000000;  // Adjust based on your needs

    uint64_t foundKey = 0;
    bool keyFound = false;

    auto startTime = std::chrono::high_resolution_clock::now();

    while (!keyFound && globalLowerBound < globalUpperBound) {
        uint64_t localLowerBound = globalLowerBound + rank * chunkSize;
        uint64_t localUpperBound = std::min(localLowerBound + chunkSize, globalUpperBound);

        foundKey = keySearch.searchRange(localLowerBound, localUpperBound);

        if (foundKey != 0) {
            keyFound = true;
            for (int i = 0; i < size; ++i) {
                MPI_Send(&foundKey, 1, MPI_UINT64_T, i, 0, MPI_COMM_WORLD);
            }
            break;
        }

        MPI_Allreduce(MPI_IN_PLACE, &keyFound, 1, MPI_C_BOOL, MPI_LOR, MPI_COMM_WORLD);
        if (keyFound) {
            MPI_Recv(&foundKey, 1, MPI_UINT64_T, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            break;
        }

        globalLowerBound += size * chunkSize;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = endTime - startTime;

    if (rank == 0) {
        if (keyFound) {
            std::cout << "Key found: " << foundKey << std::endl;

            // Verify the found key
            std::vector<unsigned char> decrypted(paddedLength);
            keyToArray(foundKey, keyArray, 8);
            encryptionAlgo->decrypt(keyArray, ciphertext.data(), decrypted.data(), paddedLength);
            decrypted.push_back('\0');

            std::cout << "Decrypted text: " << reinterpret_cast<char*>(decrypted.data()) << std::endl;
        } else {
            std::cout << "Key not found in the specified range." << std::endl;
        }
        std::cout << "Execution time: " << duration.count() << " seconds" << std::endl;
    }

    MPI_Finalize();
    return 0;
}
