# Compiler settings
CXX = g++
MPICXX = mpic++
CXXFLAGS = -Wall -O2
LDFLAGS = -lssl -lcrypto

# Directories
BIN_DIR = bin
SRC_DIR = src

# Source files
MPI_SRC = $(SRC_DIR)/mpi_bruteforce.cpp
SEQ_SRC = $(SRC_DIR)/naive_sequential.cpp

# Output binaries
MPI_BIN = $(BIN_DIR)/mpi_bruteforce
SEQ_BIN = $(BIN_DIR)/naive_sequential

# Default target
all: directories $(MPI_BIN) $(SEQ_BIN)

# Create necessary directories
directories:
	mkdir -p $(BIN_DIR)

# Compile MPI-based brute-force program
$(MPI_BIN): $(MPI_SRC)
	$(MPICXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile sequential brute-force program
$(SEQ_BIN): $(SEQ_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Clean up binaries
clean:
	rm -rf $(BIN_DIR)/*

# Clean all generated files including directories
distclean: clean
	rm -rf $(BIN_DIR)

.PHONY: all directories clean distclean
