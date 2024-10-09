/**
 * @file naive_sequential.cpp
 * @brief Sequential program to encrypt and brute-force decrypt a plaintext using OpenSSL's DES.
 *
 * @note Compile with OpenSSL:
 * g++ -o naive_sequential naive_sequential.cpp -lssl -lcrypto
 *
 * Example usage:
 * ./naive_sequential plaintext.txt 123456 search_phrase.txt
 *
 * @date October 2024
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/des.h>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <locale>

#define DEBUG 0  // Set to 1 to enable debug messages

/**
 * @brief Trims leading whitespace from the start of a string (in place).
 *
 * This function removes all leading whitespace characters from the input string `s`,
 * modifying the string in place.
 *
 * @param s The string to be trimmed.
 */
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

/**
 * @brief Trims trailing whitespace from the end of a string (in place).
 *
 * This function removes all trailing whitespace characters from the input string `s`,
 * modifying the string in place.
 *
 * @param s The string to be trimmed.
 */
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

/**
 * @brief Trims leading and trailing whitespace from both ends of a string (in place).
 *
 * This function removes all leading and trailing whitespace characters from the input string `s`,
 * modifying the string in place. It combines the functionality of `ltrim` and `rtrim`.
 *
 * @param s The string to be trimmed.
 */
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
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

    // Check if the key is weak or has incorrect parity
    if (DES_set_key_checked(&keyBlock, &keySchedule) != 0) {
        std::cerr << "Encryption key error in DES_set_key_checked" << std::endl;
        exit(1);
    }

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

    // Check if the key is weak or has incorrect parity
    if (DES_set_key_checked(&keyBlock, &keySchedule) != 0) {
        #if DEBUG
        std::cerr << "Decryption key error in DES_set_key_checked" << std::endl;
        #endif
        return;  // Skip decryption with this key
    }

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((const_DES_cblock*)(ciphertext + i), (DES_cblock*)(plaintext + i), &keySchedule, DES_DECRYPT);
    }

    #pragma GCC diagnostic pop  // Restore the previous warning settings
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
 * @param searchPhrase The phrase to search for in the decrypted text.
 * @return true If the decrypted text contains the search phrase.
 * @return false Otherwise.
 */
bool tryKey(long key, const unsigned char* ciphertext, int len, const std::string& searchPhrase) {
    unsigned char temp[len + 1];
    unsigned char keyArray[8];

    longToKey(key, keyArray);
    decrypt(keyArray, ciphertext, temp, len);
    temp[len] = '\0';  // Null-terminate the decrypted text

    // Check if decryption was successful before searching
    if (strlen(reinterpret_cast<char*>(temp)) == 0) {
        return false;
    }

    return strstr(reinterpret_cast<char*>(temp), searchPhrase.c_str()) != nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <encryption_key> <search_phrase_file>" << std::endl;
        return 1;
    }

    // Load plaintext from the file, skipping empty lines
    std::ifstream inputFile(argv[1]);
    if (!inputFile) {
        std::cerr << "Failed to open input file." << std::endl;
        return 1;
    }

    std::string line;
    std::string plaintext;
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

    std::cout << "Plaintext: -" << plaintext << "-" << std::endl;

    // Load the search phrase from the file, skipping empty lines
    std::ifstream searchPhraseFile(argv[3]);
    if (!searchPhraseFile) {
        std::cerr << "Failed to open search phrase file." << std::endl;
        return 1;
    }

    std::string searchLine;
    std::string searchPhrase;
    firstLine = true; // Flag to handle spacing correctly
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

    std::cout << "Search phrase: -" << searchPhrase << "-" << std::endl;

    // Make sure the plaintext length is a multiple of 8
    int paddedLength = ((plaintext.size() + 7) / 8) * 8;
    unsigned char plaintextBuffer[paddedLength];
    memset(plaintextBuffer, 0, paddedLength);
    memcpy(plaintextBuffer, plaintext.c_str(), plaintext.size());

    // Convert encryption key to 8-byte DES key
    unsigned char keyArray[8];
    long encryptionKey = std::stol(argv[2]);
    longToKey(encryptionKey, keyArray);

    // Encrypt the plaintext
    unsigned char ciphertext[paddedLength];

    encrypt(keyArray, plaintextBuffer, ciphertext, paddedLength);

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Brute-force decryption
    long upperBound = (1L << 56);  // Adjusted for testing purposes (2^16)
    for (long key = 0; key < upperBound; ++key) {
        if (tryKey(key, ciphertext, paddedLength, searchPhrase)) {
            unsigned char decryptedText[paddedLength + 1];
            longToKey(key, keyArray);
            decrypt(keyArray, ciphertext, decryptedText, paddedLength);
            decryptedText[paddedLength] = '\0';
            std::cout << "Key found: " << key << "\nDecrypted text:-" << decryptedText << "-" << std::endl;
            break;
        }
    }

    // End timing
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "Execution time: " << duration.count() << " seconds" << std::endl;

    return 0;
}
