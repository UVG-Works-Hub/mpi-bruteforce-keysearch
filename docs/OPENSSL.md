# How to Fix the `openssl/des.h` Not Found Error

This guide walks you through resolving the "fatal error: openssl/des.h: No such file or directory" error that occurs during compilation. This error indicates that the OpenSSL development libraries are either not installed or the compiler cannot find them.

## Prerequisites

- Ensure you have `sudo` privileges on your system to install packages.
- The following instructions apply to Linux distributions like Ubuntu, Debian, and Raspberry Pi OS. The commands may vary for other operating systems.

## Step 1: Install OpenSSL Development Libraries

First, install the OpenSSL development libraries, which include the necessary header files (e.g., `openssl/des.h`).

### On Ubuntu/Debian/Raspberry Pi OS

1. **Update the package list:**
    ```bash
    sudo apt-get update
    ```

2. **Install the OpenSSL development package:**
    ```bash
    sudo apt-get install libssl-dev
    ```

    - `libssl-dev` provides the headers and libraries needed to use OpenSSL, including `openssl/des.h`.

3. **Verify the installation:**
    After installing, verify that `openssl/des.h` is present in the `/usr/include/openssl` directory:
    ```bash
    ls /usr/include/openssl/des.h
    ```
    If the file exists, the installation was successful.

## Step 2: Confirm the Compiler Can Find OpenSSL

### Update the Include Path (If Necessary)

If the compiler still cannot find `openssl/des.h`, you might need to explicitly tell the compiler where to find the OpenSSL headers and libraries. Modify the `Makefile` to include the necessary paths:

1. **Modify the `CXXFLAGS` and `LDFLAGS` in your `Makefile` to specify the OpenSSL paths:**

    Update the `CXXFLAGS` to include the OpenSSL directory and the `LDFLAGS` to include the library path:
    ```makefile
    CXXFLAGS = -Wall -O2 -I/usr/include/openssl
    LDFLAGS = -L/usr/lib -lssl -lcrypto
    ```

    - `-I/usr/include/openssl`: This tells the compiler to look for header files in the OpenSSL directory.
    - `-L/usr/lib`: Specifies the library directory to link against OpenSSL.

## Step 3: Check OpenSSL Installation (Optional)

You can also check if OpenSSL is installed correctly and its version using:
```bash
openssl version
```
This should display the installed version of OpenSSL (e.g., `OpenSSL 1.1.1f  31 Mar 2020`).

## Step 4: Recompile the Program

Once you have installed `libssl-dev` and updated the `Makefile` if necessary, try compiling the program again:
```bash
make
```

## Troubleshooting

If the error persists, consider the following steps:

1. **Double-check the OpenSSL path:**
    Make sure `openssl/des.h` is located in `/usr/include/openssl/`. If it’s located elsewhere, update the `-I` path in the `Makefile` accordingly.

2. **Ensure the `libssl-dev` package is installed:**
    Run:
    ```bash
    dpkg -l | grep libssl-dev
    ```
    This command will list the installed OpenSSL development package. If it's not listed, re-run the installation command:
    ```bash
    sudo apt-get install libssl-dev
    ```

3. **Check the Compiler:**
    Ensure that you are using a compatible compiler (`g++` for C++) that supports linking with OpenSSL.

## Additional Notes

- For other Linux distributions (e.g., Fedora, Arch Linux), the package name may differ. Use the appropriate package manager (e.g., `dnf`, `pacman`) to install the OpenSSL development libraries.
- On macOS, use `brew` to install OpenSSL:
    ```bash
    brew install openssl
    ```
    Then, update your `Makefile` to include the paths where Homebrew installs OpenSSL:
    ```makefile
    CXXFLAGS = -Wall -O2 -I/usr/local/opt/openssl/include
    LDFLAGS = -L/usr/local/opt/openssl/lib -lssl -lcrypto
    ```
