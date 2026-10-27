#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <vector>

class Logger {
private:
    std::string log_path;

public:
    explicit Logger(const std::string& path);
    void write_log(const std::string& message, bool is_critical = false);
};

class ServerCommunicator {
private:
    int port;
    int server_fd;
    Logger& logger;

public:
    ServerCommunicator(int p, Logger& log_ref);
    void start_listening();
    int accept_client();
    ~ServerCommunicator();
};

class AuthManager {
private:
    const std::string valid_user = "user";
    const std::string valid_pass = "P@ssW0rd";
    Logger& logger;
    std::string generate_salt();

public:
    explicit AuthManager(Logger& log_ref);
    bool authenticate(int client_sock);
};

class Calculator {
private:
    Logger& logger;

public:
    explicit Calculator(Logger& log_ref);
    void process_vectors(int client_sock);
};

#endif 

