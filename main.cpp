#include <iostream>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <boost/program_options.hpp>
#include "server.h"

namespace po = boost::program_options;

class ServerApp {
private:
    int port;
    std::string log_path;

public:
    ServerApp() : port(33333), log_path("vcalc.log") {}

    int run(int argc, char* argv[]) {
        std::string data_type, hash_type, salt_side;

        try {
            po::options_description desc("Доступные параметры");
            desc.add_options()
                ("help,h", "Показать справку")
                ("type,T", po::value<std::string>(&data_type)->required(), "Тип данных (float)")
                ("hash,H", po::value<std::string>(&hash_type)->required(), "Тип хэша (SHA1)")
                ("salt,S", po::value<std::string>(&salt_side)->required(), "Сторона соли (server)")
                ("log,l", po::value<std::string>(&log_path)->default_value("vcalc.log"), "Путь к файлу логов");

            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, desc), vm);

            if (vm.count("help") || argc == 1) {
                std::cout << desc << std::endl;
                return 0;
            }

            po::notify(vm);

            if (hash_type != "SHA1" || salt_side != "server" || data_type != "float") {
                std::cerr << "[Критическая ошибка] Параметры не соответствуют требуемым\n"
                          << "Требуется запускать: -T float -H SHA1 -S server" << std::endl;
                return 1;
            }

            Logger logger(log_path);
            ServerCommunicator communicator(port, logger);
            communicator.start_listening();

            AuthManager auth(logger);
            Calculator calc(logger);

            while (true) {
                int client_sock = -1;
                try {
                    client_sock = communicator.accept_client();
                    std::cout << "\n[Сессия] Новое подключение клиента..." << std::endl;
                    
                    if (auth.authenticate(client_sock)) {
                        std::cout << "[Сессия] Авторизация успешна. Начинаем расчет..." << std::endl;
                        calc.process_vectors(client_sock);
                    } else {
                        std::cout << "[Сессия] Ошибка авторизации. Соединение закрыто." << std::endl;
                    }
                    close(client_sock);
		} catch (const std::exception& e) {
                    std::string error_msg = e.what();
                    if (error_msg.find("приеме") != std::string::npos || 
                        error_msg.find("accept") != std::string::npos ||
                        error_msg.find("Accept") != std::string::npos) {
                        if (client_sock != -1) close(client_sock);
                        continue; 
                    }
                  
                    logger.write_log(std::string("Сбой в сессии клиента: ") + error_msg);
                    if (client_sock != -1) close(client_sock);
                }
            }

        } catch (const std::exception& e) {
            std::cerr << "[Критическая ошибка сервера] " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }
};

int main(int argc, char* argv[]) {
    ServerApp app;
    return app.run(argc, argv);
}
