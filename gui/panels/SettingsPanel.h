#pragma once
#include "imgui.h"
#include "../../include/ImGuiColors.h"
#include "../../include/RuleEngine.h"
#include "../../include/PacketProcessor.h"
#include "../../include/TrafficMonitor.h"
#include "../../include/FileLogger.h"
#include "../../include/MongoLogger.h"
#include "../../include/FirewallStats.h"
#include "../../include/Stack.h"

class SettingsPanel {
public:
    SettingsPanel(RuleEngine* e, PacketProcessor* p, TrafficMonitor* m, FileLogger* fl, MongoLogger* ml, FirewallStats* s, Stack* st)
        : engine_(e), processor_(p), monitor_(m), logger_(fl), mongoLogger_(ml), stats_(s), history_(st) {}
    void Render();
private:
    RuleEngine* engine_;
    PacketProcessor* processor_;
    TrafficMonitor* monitor_;
    FileLogger* logger_;
    MongoLogger* mongoLogger_;
    FirewallStats* stats_;
    Stack* history_;

    bool firewallEnabled_ = true;
    int defaultAction_ = 1;
    bool logAll_ = true;
    bool threatDetection_ = true;
    bool mongoEnabled_ = false;
    char mongoURI_[256] = "mongodb://localhost:27017";
    char mongoDb_[128] = "firewall_db";
    bool mongoConnected_ = false;
};
