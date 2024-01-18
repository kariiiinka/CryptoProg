#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <string>
#include <cstring>
#include <fstream>
int main() {
    std::cout<<"Для завершения работы программы введите 0"<<std::endl;
    std::cout<<"___________________________________________________________________________________"<<std::endl;
    while (true){
        std::string infilename;
        std::cout<<"Введите имя файла для шифрования его содержимого: ";
        std::cin>>infilename;
        if (infilename=="0"){
            std::cout<<"Пользователь завершил работу программы"<<std::endl;
            exit(0);
        }
        std::cout<<"Введите строку для записи в файл для шифрования: ";
        std::string test;
        std::cin>>test;
        if (test=="0"){
            std::cout<<"Пользователь завершил работу программы"<<std::endl;
            exit(0);
        }
        std::string outfilename;
        std::cout<<"Введите имя файла для сохранения результата шифрования ";
        std::cin>>outfilename;
        if (outfilename=="0"){
            std::cout<<"Пользователь завершил работу программы"<<std::endl;
            exit(0);
        }
        std::ofstream infile(infilename);
        if (infile.is_open()) {
            infile << test;
            infile.close();
        }
        CryptoPP::SHA256 hash;
        CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::FileSource(infilename.c_str(), true,
                            new CryptoPP::HashFilter(hash,
                                new CryptoPP::ArraySink(digest, sizeof(digest))));
        std::string hashString;
        CryptoPP::StringSource(digest, sizeof(digest), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashString)));
        CryptoPP::StringSource(hashString, true, new CryptoPP::FileSink(outfilename.c_str()));
        std::cout<<"Процесс успешен"<<std::endl;
        std::cout<<"___________________________________________________________________________________"<<std::endl;
    }
    return 0;
}