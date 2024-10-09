# =====================================================================
# Makefile for Compiling MPI and Sequential Brute-Force Programs
# =====================================================================

# Compiler settings
CXX = g++
MPICXX = mpic++
CXXFLAGS = -Wall -O2 -std=c++11
OPT_CXXFLAGS = -Wall -O3 -std=c++11 -fopenmp -march=native
LDFLAGS = -lssl -lcrypto

# Directories
BIN_DIR = bin
SRC_DIR = src

# Source files
MPI_ORIGINAL_SRC = $(SRC_DIR)/mpi_bruteforce.cpp
MPI_V1_SRC = $(SRC_DIR)/mpi_bruteforce_v1.cpp
MPI_V2_SRC = $(SRC_DIR)/mpi_bruteforce_v2.cpp
SEQ_SRC = $(SRC_DIR)/naive_sequential.cpp

# Output binaries
MPI_ORIGINAL_BIN = $(BIN_DIR)/mpi_bruteforce_original
MPI_V1_BIN = $(BIN_DIR)/mpi_bruteforce_v1
MPI_V2_BIN = $(BIN_DIR)/mpi_bruteforce_v2
SEQ_BIN = $(BIN_DIR)/naive_sequential

# Default target
all: directories $(MPI_ORIGINAL_BIN) $(MPI_V1_BIN) $(MPI_V2_BIN) $(SEQ_BIN)

# Create necessary directories
directories:
	@mkdir -p $(BIN_DIR)

# Compile original MPI-based brute-force program
$(MPI_ORIGINAL_BIN): $(MPI_ORIGINAL_SRC)
	@echo "Compiling original MPI brute-force program..."
	$(MPICXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile MPI-based brute-force program version 1
$(MPI_V1_BIN): $(MPI_V1_SRC)
	@echo "Compiling MPI brute-force version 1..."
	$(MPICXX) $(OPT_CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile MPI-based brute-force program version 2
$(MPI_V2_BIN): $(MPI_V2_SRC)
	@echo "Compiling MPI brute-force version 2..."
	$(MPICXX) $(OPT_CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile sequential brute-force program
$(SEQ_BIN): $(SEQ_SRC)
	@echo "Compiling sequential brute-force program..."
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Clean up binaries
clean:
	@echo "Cleaning up binaries..."
	@rm -f $(BIN_DIR)/*

# Clean all generated files including directories
distclean: clean
	@echo "Removing bin directory..."
	@rm -rf $(BIN_DIR)

# Phony targets
.PHONY: all directories clean distclean
