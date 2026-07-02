#pragma once
#include "imgui.h"
#include "../../include/RuleEngine.h"
#include "../../include/FirewallStats.h"
#include <vector>
#include <string>

class ThreatsPanel {
public:
    ThreatsPanel(FirewallStats* s, RuleEngine* e) : stats_(s), engine_(e) {}
    void Render();
    void SyncThreats(FirewallStats* stats);
private:
    FirewallStats* stats_;
    RuleEngine* engine_;
    int filterTab_ = 0;
    std::vector<ThreatAlert> threats_;
};
