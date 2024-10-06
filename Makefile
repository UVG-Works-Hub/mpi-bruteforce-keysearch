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
MPI_SRC = $(SRC_DIR)/mpi_bruteforce.cpp
MPI_OPT_SRC = $(SRC_DIR)/mpi_bruteforce_optimized.cpp
MPI_REOPT_SRC = $(SRC_DIR)/mpi_bruteforce_reoptimized.cpp
SEQ_SRC = $(SRC_DIR)/naive_sequential.cpp

# Output binaries
MPI_BIN = $(BIN_DIR)/mpi_bruteforce
MPI_OPT_BIN = $(BIN_DIR)/mpi_bruteforce_optimized
MPI_REOPT_BIN = $(BIN_DIR)/mpi_bruteforce_reoptimized
SEQ_BIN = $(BIN_DIR)/naive_sequential

# Default target
all: directories $(MPI_BIN) $(MPI_OPT_BIN) $(MPI_REOPT_BIN) $(SEQ_BIN)

# Create necessary directories
directories:
	@mkdir -p $(BIN_DIR)

# Compile original MPI-based brute-force program
$(MPI_BIN): $(MPI_SRC)
	@echo "Compiling original MPI brute-force program..."
	$(MPICXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile optimized MPI-based brute-force program
$(MPI_OPT_BIN): $(MPI_OPT_SRC)
	@echo "Compiling optimized MPI brute-force program..."
	$(MPICXX) $(OPT_CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile reoptimized MPI-based brute-force program
$(MPI_REOPT_BIN): $(MPI_REOPT_SRC)
	@echo "Compiling reoptimized MPI brute-force program..."
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
