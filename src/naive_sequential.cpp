/**
 * @file naive_sequential.cpp
 * @brief Sequential brute force key search to decrypt ciphertext using OpenSSL's DES.
 *
 * The program performs the following steps:
 * 1. Iterates over all possible keys to find the correct one that decrypts the ciphertext.
 * 2. Validates the decryption by checking for a known keyword in the plaintext.
 * 3. Prints the found key and decrypted text.
 *
 * @note Compile with OpenSSL:
 * g++ -o naive_sequential naive_sequential.cpp -lssl -lcrypto
 *
 * @date October 2024
 */

#include <iostream>
#include <cstring>
#include <openssl/des.h>

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

int main() {
    // Ciphertext to decrypt
    unsigned char ciphertext[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215};
    int ciphertextLength = sizeof(ciphertext);

    long upperBound = (1L << 56);  // Upper bound for DES keys (2^56)

    for (long key = 0; key < upperBound; ++key) {
        if (tryKey(key, ciphertext, ciphertextLength)) {
            unsigned char decryptedText[ciphertextLength + 1];
            unsigned char keyArray[8];
            longToKey(key, keyArray);
            decrypt(keyArray, ciphertext, decryptedText, ciphertextLength);
            decryptedText[ciphertextLength] = '\0';
            std::cout << "Key found: " << key << " Decrypted text: " << decryptedText << std::endl;
            break;
        }
    }

    return 0;
}
