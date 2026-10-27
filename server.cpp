#include "server.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <stdexcept>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

namespace CPP = CryptoPP;

Logger::Logger(const std::string& path) : log_path(path) {}

void Logger::write_log(const std::string& message, bool is_critical) {
    std::ofstream log_file(log_path, std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "[Ошибка] Не удалось открыть файл лога: " << log_path << std::endl;
        return;
    }

    std::time_t now = std::time(NULL);
    char time_buf[80];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    log_file << "[" << time_buf << "] [" << (is_critical ? "CRITICAL" : "ERROR") << "] " << message << std::endl;
}

ServerCommunicator::ServerCommunicator(int p, Logger& log_ref) : port(p), server_fd(-1), logger(log_ref) {}

void ServerCommunicator::start_listening() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        logger.write_log("Не удалось создать сетевой сокет", true);
        throw std::runtime_error("Ошибка: Не удалось создать сетевой сокет");
    }

    struct timeval timeout;
    timeout.tv_sec = 20;
    timeout.tv_usec = 0;
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        logger.write_log("Не удалось занять порт (bind)", true);
        close(server_fd);
        throw std::runtime_error("Ошибка: Не удалось занять порт (bind)");
    }

    if (listen(server_fd, 3) < 0) {
        logger.write_log("Не удалось включить прослушивание сокета", true);
        close(server_fd);
        throw std::runtime_error("Ошибка: Не удалось включить прослушивание сокета");
    }
    std::cout << "[ОК] Сервер запущен на порту " << port << std::endl;
}

int ServerCommunicator::accept_client() {
    int client_sock = accept(server_fd, NULL, NULL);
    if (client_sock < 0) {
        throw std::runtime_error("Ошибка при приеме подключения клиента");
    }
    return client_sock;
}

ServerCommunicator::~ServerCommunicator() {
    if (server_fd != -1) {
        close(server_fd);
    }
}

AuthManager::AuthManager(Logger& log_ref) : logger(log_ref) {}

std::string AuthManager::generate_salt() {
    CPP::AutoSeededRandomPool prng;
    uint64_t random_val;
    prng.GenerateBlock((CPP::byte*)&random_val, sizeof(random_val));

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << random_val;
    return ss.str();
}

bool AuthManager::authenticate(int client_sock) {
    char buffer[1024];
    std::memset(buffer, 0, sizeof(buffer));

    int rc = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (rc <= 0) {
        logger.write_log("Не получен логин от клиента (обрыв связи).");
        return false;
    }

    std::string client_login(buffer);
    while (!client_login.empty() && (client_login.back() == '\n' || client_login.back() == '\r')) {
        client_login.pop_back();
    }

    if (client_login != valid_user) {
        logger.write_log("Попытка входа с неверным логином: " + client_login);
        send(client_sock, "ERR", 3, 0);
        return false;
    }

    std::string salt = generate_salt();
    send(client_sock, salt.c_str(), salt.length(), 0);

    std::memset(buffer, 0, sizeof(buffer));
    rc = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (rc <= 0) {
        logger.write_log("Клиент отключился на этапе отправки хэша");
        return false;
    }

    std::string client_hash(buffer);
    while (!client_hash.empty() && (client_hash.back() == '\n' || client_hash.back() == '\r')) {
        client_hash.pop_back();
    }

    CPP::SHA1 sha1;
    std::string calculated_hash;
    std::string salt_pass = salt + valid_pass;

    CPP::StringSource(salt_pass, true,
        new CPP::HashFilter(sha1,
            new CPP::HexEncoder(
                new CPP::StringSink(calculated_hash), true
            )
        )
    );

    if (client_hash == calculated_hash) {
        send(client_sock, "OK", 2, 0);
        return true;
    } else {
        logger.write_log("Отказ авторизации: неверный хэш для пользователя " + valid_user);
        send(client_sock, "ERR", 3, 0);
        return false;
    }
}

Calculator::Calculator(Logger& log_ref) : logger(log_ref) {}

void Calculator::process_vectors(int client_sock) {
    uint32_t num_vectors = 0;
    if (recv(client_sock, &num_vectors, sizeof(num_vectors), 0) <= 0) {
        logger.write_log("Не удалось получить количество векторов от клиента");
        return;
    }

    for (uint32_t i = 0; i < num_vectors; ++i) {
        uint32_t vector_size = 0;
        if (recv(client_sock, &vector_size, sizeof(vector_size), 0) <= 0) {
            logger.write_log("Ошибка чтения размера вектора №" + std::to_string(i + 1));
            return;
        }

        std::vector<float> vector_data(vector_size);
        int total_bytes = vector_size * sizeof(float);
        int bytes_read = 0;
        char* data_ptr = (char*)vector_data.data();

        while (bytes_read < total_bytes) {
            int ret = recv(client_sock, data_ptr + bytes_read, total_bytes - bytes_read, 0);
            if (ret <= 0) {
                logger.write_log("Клиент оборвал передачу элементов вектора №" + std::to_string(i + 1));
                return;
            }
            bytes_read += ret;
        }

        float product = 1.0f;
        for (size_t j = 0; j < vector_data.size(); ++j) {
            product *= vector_data[j];
        }

        if (std::isinf(product)) {
            if (product > 0) {
                product = std::numeric_limits<float>::max();
            } else {
                product = -std::numeric_limits<float>::max();
            }
            logger.write_log("Предупреждение: Вектор №" + std::to_string(i + 1) + " вызвал переполнение float.");
        }

        if (send(client_sock, &product, sizeof(product), 0) <= 0) {
            logger.write_log("Не удалось отправить результат вектора №" + std::to_string(i + 1));
            return;
        }
    }
    std::cout << "[Успех] Все полученные векторы успешно посчитаны" << std::endl;
}
