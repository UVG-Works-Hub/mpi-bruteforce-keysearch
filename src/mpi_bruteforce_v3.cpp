#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/des.h>
#include <mpi.h>
#include <chrono>
#include <algorithm>
#include <vector>
#include <queue>
#include <random>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

#define DEBUG 0

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

// KeySpace class to represent a range of keys
class KeySpace {
public:
    long start;
    long end;
    double priority;

    KeySpace(long s, long e, double p) : start(s), end(e), priority(p) {}

    bool operator<(const KeySpace& other) const {
        return priority < other.priority;
    }
};

// Pipeline stages
enum class PipelineStage {
    GENERATE,
    ENCRYPT,
    COMPARE
};

// Shared data structure for pipeline
struct PipelineData {
    std::queue<long> generatedKeys;
    std::queue<std::pair<long, std::vector<unsigned char>>> encryptedData;
    std::atomic<bool> keyFound{false};
    std::atomic<long> foundKey{0};
    std::mutex mtx;
    std::condition_variable cv;
};

// Function to generate intelligent key spaces
std::vector<KeySpace> generateIntelligentKeySpaces(long start, long end, int numSpaces) {
    std::vector<KeySpace> spaces;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);

    long range = end - start;
    long spaceSize = range / numSpaces;

    for (int i = 0; i < numSpaces; ++i) {
        long spaceStart = start + i * spaceSize;
        long spaceEnd = (i == numSpaces - 1) ? end : spaceStart + spaceSize;
        double priority = dis(gen);  // Random priority for this example. Can be replaced with heuristics.
        spaces.emplace_back(spaceStart, spaceEnd, priority);
    }

    std::sort(spaces.begin(), spaces.end());  // Sort by priority
    return spaces;
}

class ParallelKeySearch {
private:
    const unsigned char* ciphertext;
    int len;
    const std::string& searchPhrase;

public:
    ParallelKeySearch(const unsigned char* ct, int l, const std::string& phrase)
        : ciphertext(ct), len(l), searchPhrase(phrase) {}

    bool tryKey(long key) const {
        unsigned char keyArray[8];
        longToKey(key, keyArray);

        unsigned char decrypted[len + 1];
        decrypt(keyArray, ciphertext, decrypted, len);
        decrypted[len] = '\0';

        return strstr(reinterpret_cast<char*>(decrypted), searchPhrase.c_str()) != nullptr;
    }

    void pipelineGenerate(KeySpace space, PipelineData& data) {
        for (long key = space.start; key < space.end; ++key) {
            {
                std::unique_lock<std::mutex> lock(data.mtx);
                data.generatedKeys.push(key);
            }
            data.cv.notify_one();
            if (data.keyFound) break;
        }
    }

    void pipelineEncrypt(PipelineData& data) {
        while (!data.keyFound) {
            long key;
            {
                std::unique_lock<std::mutex> lock(data.mtx);
                data.cv.wait(lock, [&]() { return !data.generatedKeys.empty() || data.keyFound; });
                if (data.keyFound) break;
                key = data.generatedKeys.front();
                data.generatedKeys.pop();
            }

            unsigned char keyArray[8];
            longToKey(key, keyArray);

            std::vector<unsigned char> decrypted(len);
            decrypt(keyArray, ciphertext, decrypted.data(), len);

            {
                std::unique_lock<std::mutex> lock(data.mtx);
                data.encryptedData.push({key, std::move(decrypted)});
            }
            data.cv.notify_one();
        }
    }

    void pipelineCompare(PipelineData& data) {
        while (!data.keyFound) {
            std::pair<long, std::vector<unsigned char>> item;
            {
                std::unique_lock<std::mutex> lock(data.mtx);
                data.cv.wait(lock, [&]() { return !data.encryptedData.empty() || data.keyFound; });
                if (data.keyFound) break;
                item = std::move(data.encryptedData.front());
                data.encryptedData.pop();
            }

            if (strstr(reinterpret_cast<char*>(item.second.data()), searchPhrase.c_str()) != nullptr) {
                data.keyFound = true;
                data.foundKey = item.first;
                data.cv.notify_all();
                break;
            }
        }
    }

    long searchRange(KeySpace space) {
        PipelineData pipelineData;

        std::thread generateThread(&ParallelKeySearch::pipelineGenerate, this, space, std::ref(pipelineData));
        std::thread encryptThread(&ParallelKeySearch::pipelineEncrypt, this, std::ref(pipelineData));
        std::thread compareThread(&ParallelKeySearch::pipelineCompare, this, std::ref(pipelineData));

        generateThread.join();
        encryptThread.join();
        compareThread.join();

        return pipelineData.foundKey;
    }
};

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);

    int numProcesses, processId;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Comm_size(comm, &numProcesses);
    MPI_Comm_rank(comm, &processId);

    std::string plaintext;
    std::string searchPhrase;
    long encryptionKey;

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

        // Convert encryption key to long
        encryptionKey = std::stol(argv[2]);

        std::cout << "Plaintext: " << plaintext << std::endl;
        std::cout << "Search phrase: " << searchPhrase << std::endl;
    }

    // Broadcast encryption key length and value
    MPI_Bcast(&encryptionKey, 1, MPI_LONG, 0, comm);

    // Broadcast plaintext length and content
    int plaintextLength;
    if (processId == 0) {
        plaintextLength = plaintext.size();
    }
    MPI_Bcast(&plaintextLength, 1, MPI_INT, 0, comm);

    if (processId != 0) {
        plaintext.resize(plaintextLength);
    }
    MPI_Bcast(&plaintext[0], plaintextLength, MPI_CHAR, 0, comm);

    // Broadcast search phrase length and content
    int searchPhraseLength;
    if (processId == 0) {
        searchPhraseLength = searchPhrase.size();
    }
    MPI_Bcast(&searchPhraseLength, 1, MPI_INT, 0, comm);

    if (processId != 0) {
        searchPhrase.resize(searchPhraseLength);
    }
    MPI_Bcast(&searchPhrase[0], searchPhraseLength, MPI_CHAR, 0, comm);

    // Pad plaintext to multiple of 8 bytes
    int paddedLength = ((plaintext.size() + 7) / 8) * 8;
    std::vector<unsigned char> plaintextBuffer(paddedLength, 0);
    std::copy(plaintext.begin(), plaintext.end(), plaintextBuffer.begin());

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext(paddedLength);
    unsigned char keyArray[8];
    longToKey(encryptionKey, keyArray);
    encrypt(keyArray, plaintextBuffer.data(), ciphertext.data(), paddedLength);

    // Set up parallel key search
    ParallelKeySearch keySearch(ciphertext.data(), paddedLength, searchPhrase);

    // Generate intelligent key spaces
    std::vector<KeySpace> keySpaces;
    if (processId == 0) {
        keySpaces = generateIntelligentKeySpaces(0, (1L << 56) - 1, numProcesses * 10);  // 10 spaces per process
    }

    // Distribute initial key spaces
    std::vector<KeySpace> localKeySpaces;
    if (processId == 0) {
        for (int i = 0; i < numProcesses; ++i) {
            int spacesToSend = (i == numProcesses - 1) ? keySpaces.size() - (numProcesses - 1) * 10 : 10;
            MPI_Send(&spacesToSend, 1, MPI_INT, i, 0, MPI_COMM_WORLD);
            for (int j = 0; j < spacesToSend; ++j) {
                KeySpace space = keySpaces.back();
                keySpaces.pop_back();
                MPI_Send(&space, sizeof(KeySpace), MPI_BYTE, i, 1, MPI_COMM_WORLD);
            }
        }
    }

    int localSpacesCount;
    MPI_Recv(&localSpacesCount, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    for (int i = 0; i < localSpacesCount; ++i) {
        KeySpace space;
        MPI_Recv(&space, sizeof(KeySpace), MPI_BYTE, 0, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        localKeySpaces.push_back(space);
    }

    long foundKey = 0;
    bool keyFound = false;

    auto startTime = std::chrono::high_resolution_clock::now();

    // Asynchronous parallelism and dynamic load balancing
    while (!localKeySpaces.empty() && !keyFound) {
        KeySpace space = localKeySpaces.back();
        localKeySpaces.pop_back();

        foundKey = keySearch.searchRange(space);

        if (foundKey != 0) {
            keyFound = true;
            for (int i = 0; i < numProcesses; ++i) {
                MPI_Send(&foundKey, 1, MPI_LONG, i, 2, MPI_COMM_WORLD);
            }
            break;
        }

        // Check if other processes found the key
        int flag;
        MPI_Iprobe(MPI_ANY_SOURCE, 2, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
        if (flag) {
            MPI_Recv(&foundKey, 1, MPI_LONG, MPI_ANY_SOURCE, 2, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            keyFound = true;
            break;
        }

        // Request more work if local queue is empty
        if (localKeySpaces.empty() && processId != 0) {
            MPI_Send(&processId, 1, MPI_INT, 0, 3, MPI_COMM_WORLD);
            MPI_Recv(&space, sizeof(KeySpace), MPI_BYTE, 0, 4, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            if (space.start != space.end) {  // Valid space
                localKeySpaces.push_back(space);
            }
        }

        // Process 0 handles work distribution
        if (processId == 0) {
            int requestingRank;
            MPI_Status status;
            MPI_Recv(&requestingRank, 1, MPI_INT, MPI_ANY_SOURCE, 3, MPI_COMM_WORLD, &status);
            if (!keySpaces.empty()) {
                KeySpace spaceToSend = keySpaces.back();
                keySpaces.pop_back();
                MPI_Send(&spaceToSend, sizeof(KeySpace), MPI_BYTE, requestingRank, 4, MPI_COMM_WORLD);
            } else {
                KeySpace emptySpace{0, 0, 0};  // Signal no more work
                MPI_Send(&emptySpace, sizeof(KeySpace), MPI_BYTE, requestingRank, 4, MPI_COMM_WORLD);
            }
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = endTime - startTime;

    if (processId == 0) {
        if (keyFound) {
            std::cout << "Key found: " << foundKey << std::endl;

            // Verify the found key
            std::vector<unsigned char> decrypted(paddedLength);
            longToKey(foundKey, keyArray);
            decrypt(keyArray, ciphertext.data(), decrypted.data(), paddedLength);
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
