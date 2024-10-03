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

    DES_set_key_checked(&keyBlock, &keySchedule);

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

    DES_set_key_checked(&keyBlock, &keySchedule);

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

    return strstr(reinterpret_cast<char*>(temp), searchPhrase.c_str()) != nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <encryption_key> <search_phrase_file>" << std::endl;
        return 1;
    }

    // Load plaintext from the file
    std::ifstream inputFile(argv[1]);
    if (!inputFile) {
        std::cerr << "Failed to open input file." << std::endl;
        return 1;
    }

    std::string plaintext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Load the search phrase from the file
    std::ifstream searchPhraseFile(argv[3]);
    if (!searchPhraseFile) {
        std::cerr << "Failed to open search phrase file." << std::endl;
        return 1;
    }
    std::string searchPhrase((std::istreambuf_iterator<char>(searchPhraseFile)), std::istreambuf_iterator<char>());
    searchPhraseFile.close();

    // Remove any trailing newline characters from the search phrase
    if (!searchPhrase.empty() && searchPhrase[searchPhrase.length() - 1] == '\n') {
        searchPhrase.erase(searchPhrase.length() - 1);
    }

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

    // Brute-force decryption
    long upperBound = (1L << 56);  // Upper bound for DES keys (2^56)
    for (long key = 0; key < upperBound; ++key) {
        if (tryKey(key, ciphertext, paddedLength, searchPhrase)) {
            unsigned char decryptedText[paddedLength + 1];
            longToKey(key, keyArray);
            decrypt(keyArray, ciphertext, decryptedText, paddedLength);
            decryptedText[paddedLength] = '\0';
            std::cout << "Key found: " << key << " Decrypted text: " << decryptedText << std::endl;
            break;
        }
    }

    return 0;
}
