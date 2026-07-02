#pragma once
#include "imgui.h"
#include "implot.h"
#include "../../include/FirewallStats.h"
#include "../../include/ImGuiColors.h"
#include "../../include/RuleEngine.h"
#include "../../include/PacketProcessor.h"
#include "../../include/TrafficMonitor.h"
#include "../../include/Stack.h"
#include "../../include/FileLogger.h"
#include <vector>
#include <string>

class DashboardPanel {
public:
    DashboardPanel(FirewallStats* s, RuleEngine* e, PacketProcessor* p, TrafficMonitor* m, Stack* st, FileLogger* fl);
    void Render();
    void UpdateData();
    int pendingNavigation_ = -1;
private:
    void RenderStatCards();
    void RenderLiveTraffic();
    void RenderActiveRules();
    void RenderPacketLog();

    FirewallStats* stats_;
    RuleEngine* engine_;
    PacketProcessor* processor_;
    TrafficMonitor* monitor_;
    Stack* history_;
    FileLogger* logger_;

    float allowedBuffer_[60] = {0};
    float blockedBuffer_[60] = {0};
    int bufferOffset_ = 0;
    int lastAllowed_ = 0;
    int lastBlocked_ = 0;

    bool filterOpen_ = false;
    bool exportOpen_ = false;
    int filterProtocol_ = 0;
    int filterAction_ = 0;
    int filterDirection_ = 0;
    int filterTime_ = 0;
};
