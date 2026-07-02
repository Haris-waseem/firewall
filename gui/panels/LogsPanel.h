#pragma once
#include "imgui.h"
#include "../../include/ImGuiColors.h"
#include "../../include/FileLogger.h"
#include "../../include/TrafficMonitor.h"
#include <vector>
#include <string>

class LogsPanel {
public:
    LogsPanel(FileLogger* l, TrafficMonitor* m) : logger_(l), monitor_(m) {}
    void Render();
private:
    FileLogger* logger_;
    TrafficMonitor* monitor_;
    char searchBuf_[256] = "";
    bool needsRefresh_ = true;
    std::vector<std::string> logLines_;
    int filterProtocol_ = 0;
    int filterAction_ = 0;
    int filterDirection_ = 0;
    int filterTime_ = 0;
};
