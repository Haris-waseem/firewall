#pragma once
#include "imgui.h"
#include "implot.h"
#include "../../include/ImGuiColors.h"
#include "../../include/FirewallStats.h"
#include "../../include/TrafficMonitor.h"
#include "../../include/FileLogger.h"
#include <vector>
#include <string>

class TrafficPanel {
public:
    TrafficPanel(FirewallStats* s, TrafficMonitor* m, FileLogger* fl) : stats_(s), monitor_(m), logger_(fl) {}
    void Render();
    void UpdateData(FirewallStats* stats);
private:
    FirewallStats* stats_;
    TrafficMonitor* monitor_;
    FileLogger* logger_;
    int timeFilter_ = 0;
    float allowedBuf_[60] = {0};
    float blockedBuf_[60] = {0};
    int lastAllowed_ = 0;
    int lastBlocked_ = 0;
    int bufferOffset_ = 0;
};

