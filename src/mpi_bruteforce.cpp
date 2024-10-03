/**
 * @file mpi_bruteforce.cpp
 * @brief MPI program to find the private key used to encrypt a plaintext using brute force.
 * @note This program uses OpenSSL for DES decryption and Open MPI for parallel key search.
 *
 * The program performs the following steps:
 * 1. Distributes the key search space among multiple MPI processes.
 * 2. Each process decrypts a portion of the key space to find the correct key.
 * 3. Validates the decryption by checking for the presence of a known keyword in the plaintext.
 * 4. Uses non-blocking communication to notify other processes once the key is found.
 * 5. Prints the found key and the decrypted text.
 *
 * @note Compile using Open MPI and OpenSSL libraries:
 * mpic++ -o mpi_bruteforce mpi_bruteforce.cpp -lssl -lcrypto
 *
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 *
 * Example usage:
 * mpirun -np 4 ./mpi_bruteforce
 *
 * @date October 2024
 */

#include <iostream>
#include <cstring>
#include <openssl/des.h>
#include <mpi.h>

// Search phrase to verify successful decryption
const char SEARCH_PHRASE[] = " the ";

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
    DES_set_key_checked(&keyBlock, &keySchedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(ciphertext + i), (DES_cblock*)(plaintext + i), &keySchedule, DES_DECRYPT);
    }
}

/**
 * @brief Converts a long integer to an 8-byte key.
 *
 * @param key The long integer key.
 * @param keyArray The buffer to store the converted 8-byte key.
 */
void longToKey(long key, unsigned char* keyArray) {
    for (int i = 0; i < 8; ++i) {
        keyArray[7 - i] = (key >> (i * 8)) & 0xFF;
    }
}

/**
 * @brief Attempts to decrypt the ciphertext with the given key and checks for the search phrase.
 *
 * @param key The long key to test.
 * @param ciphertext The encrypted data.
 * @param len Length of the ciphertext.
 * @return true If the decrypted text contains the search phrase.
 * @return false Otherwise.
 */
bool tryKey(long key, const unsigned char* ciphertext, int len) {
    unsigned char temp[len + 1];
    unsigned char keyArray[8];

    longToKey(key, keyArray);
    decrypt(keyArray, ciphertext, temp, len);
    temp[len] = '\0';  // Null-terminate the decrypted text

    return strstr(reinterpret_cast<char*>(temp), SEARCH_PHRASE) != nullptr;
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);

    int numProcesses, processId;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Comm_size(comm, &numProcesses);
    MPI_Comm_rank(comm, &processId);

    // Define key space and range for each process
    long upperBound = (1L << 56);  // 2^56 keys for DES
    long keysPerProcess = upperBound / numProcesses;
    long lowerBound = keysPerProcess * processId;
    long upperBoundLocal = (processId == numProcesses - 1) ? upperBound : keysPerProcess * (processId + 1) - 1;

    // Ciphertext to decrypt
    unsigned char ciphertext[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215};
    int ciphertextLength = sizeof(ciphertext);

    long foundKey = 0;
    MPI_Request request;
    MPI_Irecv(&foundKey, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &request);

    // Brute-force key search
    for (long key = lowerBound; key < upperBoundLocal && foundKey == 0; ++key) {
        if (tryKey(key, ciphertext, ciphertextLength)) {
            foundKey = key;
            for (int i = 0; i < numProcesses; ++i) {
                MPI_Send(&foundKey, 1, MPI_LONG, i, 0, comm);
            }
            break;
        }
    }

    if (processId == 0) {
        MPI_Wait(&request, MPI_STATUS_IGNORE);
        unsigned char decryptedText[ciphertextLength + 1];
        unsigned char keyArray[8];
        longToKey(foundKey, keyArray);
        decrypt(keyArray, ciphertext, decryptedText, ciphertextLength);
        decryptedText[ciphertextLength] = '\0';
        std::cout << "Key found: " << foundKey << " Decrypted text: " << decryptedText << std::endl;
    }

    MPI_Finalize();
    return 0;
}
