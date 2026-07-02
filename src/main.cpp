// HAS_GUI is defined by CMakeLists.txt (target_compile_definitions)
#include <windows.h>
#include <iostream>
#include <string>
#include "../include/enums.h"
#include "../include/Packet.h"
#include "../include/Rule.h"
#include "../include/FirewallStats.h"
#include "../include/FileLogger.h"
#include "../include/MongoLogger.h"
#include "../include/MongoConfig.h"
#include "../include/Stack.h"
#include "../include/Queue.h"
#include "../include/TrafficMonitor.h"
#include "../include/RuleEngine.h"
#include "../include/PacketProcessor.h"
#include "../include/AdminCLI.h"

#ifdef HAS_GUI
#include "../gui/FirewallGUI.h"
#endif

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    bool cliMode = false;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--cli") {
            cliMode = true;
            break;
        }
    }

    std::cout << "========================================================\n";
    std::cout << "      C++ PACKET FILTERING FIREWALL SIMULATOR v1.0      \n";
    std::cout << "      DSA Major Project | COMSATS University Islamabad  \n";
    std::cout << "      Author: Haris | Class Student Submission          \n";
    std::cout << "========================================================\n";

    MongoConfig mongoConfig;
    mongoConfig.mongoURI = "mongodb://localhost:27017";
    MongoLogger mongoLogger(mongoConfig);

    FirewallStats  stats;
    stats.startTime = Packet::currentTimestamp();
    FileLogger     logger("firewall.log", "rules.conf");
    Stack          history(100);
    Queue          packetQueue(1000);
    TrafficMonitor monitor(100, 20, 10);
    RuleEngine     engine;

    // Try MongoDB first for config persistence; fall back to file-based
    bool configLoaded = false;

    if (mongoLogger.isConnected()) {
        try {
            auto mongoRules = mongoLogger.loadRules();
            if (!mongoRules.empty()) {
                engine.clearAll();
                for (const auto& r : mongoRules) engine.addRule(r);
                engine.setDefaultPolicy(Action::BLOCK); // MongoDB doesn't store default policy yet

                auto mongoBL = mongoLogger.loadBlacklist();
                for (const auto& ip : mongoBL) engine.addToBlacklist(ip);

                auto mongoWL = mongoLogger.loadWhitelist();
                for (const auto& ip : mongoWL) engine.addToWhitelist(ip);

                std::cout << "[System] Loaded configuration from MongoDB:\n";
                std::cout << "  - Rules loaded     : " << mongoRules.size() << "\n";
                std::cout << "  - Blacklisted IPs  : " << mongoBL.size() << "\n";
                std::cout << "  - Whitelisted IPs  : " << mongoWL.size() << "\n";
                configLoaded = true;
            }
        } catch (const std::exception& e) {
            std::cerr << "[System] MongoDB load error: " << e.what() << "\n";
        }
    }

    if (!configLoaded) {
        try {
            Action defaultPolicy = Action::BLOCK;
            auto rules = logger.loadRules(defaultPolicy);
            for (const auto& r : rules) engine.addRule(r);
            engine.setDefaultPolicy(defaultPolicy);

            auto blacklistIPs = logger.loadBlacklist();
            for (const auto& ip : blacklistIPs) engine.addToBlacklist(ip);

            auto whitelistIPs = logger.loadWhitelist();
            for (const auto& ip : whitelistIPs) engine.addToWhitelist(ip);

            std::cout << "[System] Loaded configuration from rules.conf:\n";
            std::cout << "  - Rules loaded     : " << rules.size() << "\n";
            std::cout << "  - Blacklisted IPs  : " << blacklistIPs.size() << "\n";
            std::cout << "  - Whitelisted IPs  : " << whitelistIPs.size() << "\n";
            std::cout << "  - Default Policy   : " << actionToStr(defaultPolicy) << "\n";
        } catch (...) {
            std::cout << "[System] No rules.conf found. Starting with empty ruleset.\n";
        }
    }

    PacketProcessor processor(engine, monitor, logger, mongoLogger, history, packetQueue, stats);

    if (cliMode) {
        AdminCLI cli(engine, processor, stats, logger, mongoLogger, history, monitor);
        std::cout << "[System] Firewall running in CLI mode. Type 'help' to see available commands.\n\n";
        cli.run();
    } else {
#ifdef HAS_GUI
        std::cout << "[System] Firewall running in GUI mode.\n";
        FirewallGUI gui(&engine, &processor, &monitor, &logger, &mongoLogger, &stats, &history, &packetQueue, nullptr);
        if (gui.Init()) {
            gui.Run();
            gui.Shutdown();
        } else {
            std::cerr << "[System] Failed to initialize GUI. Falling back to CLI mode.\n";
            AdminCLI cli(engine, processor, stats, logger, mongoLogger, history, monitor);
            cli.run();
        }
#else
        std::cout << "[System] GUI not available. Running in CLI mode.\n";
        AdminCLI cli(engine, processor, stats, logger, mongoLogger, history, monitor);
        cli.run();
#endif
    }

    std::cout << "\n[System] Shutting down firewall. Saving active state...\n";
    try {
        // Save to MongoDB (primary)
        if (mongoLogger.isConnected()) {
            mongoLogger.saveRules(engine.getAllRules());
            mongoLogger.saveBlacklist(engine.getBlacklistIPs());
            mongoLogger.saveWhitelist(engine.getWhitelistIPs());
            std::cout << "[System] State persisted to MongoDB.\n";
        }
        // Also save to file as backup
        logger.saveRules(engine.getAllRules(), engine.getDefaultPolicy());
        logger.saveBlacklist(engine.getBlacklistIPs());
        logger.saveWhitelist(engine.getWhitelistIPs());
        std::cout << "[System] State persisted to rules.conf (backup).\n";
    } catch (const std::exception& e) {
        std::cerr << "[System] Error during state persistence: " << e.what() << "\n";
    }

    return 0;
}
