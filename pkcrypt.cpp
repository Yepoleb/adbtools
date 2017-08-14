#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstddef>

// Link with cryptopp
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"


const int BLOCKSIZE = CryptoPP::AES::BLOCKSIZE;
// All zero IV
const byte IV[BLOCKSIZE] = {0x00};

int read_file(const std::string& filename, std::vector<char>& data)
{
    std::ifstream stream(filename, std::ios::in | std::ios::binary | std::ios::ate);
    if (!stream.is_open()) {
        return 1;
    }
    std::size_t file_size(stream.tellg());
    stream.seekg(0);
    data.resize(file_size);
    stream.read(data.data(), file_size);
    return 0;
}

int write_file(const std::string& filename, const std::vector<char>& data)
{
    std::ofstream stream(filename, std::ios::out | std::ios::binary);
    if (!stream.is_open()) {
        return 1;
    }
    stream.write(data.data(), data.size());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        std::cerr << "Usage: pkcrypt sym_encrypt|sym_decrypt <key> <in> <out>\n";
        return 1;
    }

    std::string mode(argv[1]);
    if ((mode != "sym_encrypt") && (mode != "sym_decrypt")) {
        std::cerr << "Error: First argument must be sym_encrypt or sym_decrypt.\n";
        return 1;
    }

    const char* key_filename(argv[2]);
    const char* in_filename(argv[3]);
    const char* out_filename(argv[4]);

    std::vector<char> pem_data;
    if (read_file(key_filename, pem_data)) {
        std::cerr << "Error: Failed to read key file\n";
        return 1;
    }
    if (pem_data.empty()) {
        std::cerr << "Error: PEM file is empty\n";
        return 1;
    }

    std::vector<char> in_data;
    if (read_file(in_filename, in_data)) {
        std::cerr << "Error: Failed to read input file\n";
        return 1;
    }
    if (in_data.empty()) {
        std::cerr << "Error: Input file is empty\n";
        return 1;
    }

    std::vector<char> out_data(in_data.size());

    const char* key = pem_data.data() + 32;

    if (mode == "sym_encrypt") {
        char padding_length = BLOCKSIZE - (in_data.size() % BLOCKSIZE);
        if (padding_length != BLOCKSIZE) {
            in_data.resize(in_data.size() + padding_length, padding_length);
        }
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cipher;
        cipher.SetKeyWithIV((const byte*)key, 16, IV);
        cipher.ProcessData(
            (byte*)out_data.data(), (const byte*)in_data.data(), in_data.size()
        );
    } else {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cipher;
        cipher.SetKeyWithIV((const byte*)key, 16, IV);
        cipher.ProcessData(
            (byte*)out_data.data(), (const byte*)in_data.data(), in_data.size()
        );
        char padding_length = out_data.back();
        if ((padding_length < BLOCKSIZE) && (padding_length < out_data.size())) {
            bool padding_valid = true;
            for (int i = 0; i < padding_length; i++) {
                if (out_data[i] != padding_length) {
                    padding_valid = false;
                    break;
                }
            }
            if (padding_valid) {
                out_data.resize(out_data.size() - padding_length);
            }
        }
    }

    if (write_file(out_filename, out_data)) {
        std::cerr << "Error: Failed to write output file\n";
        return 1;
    }
    return 0;
}
