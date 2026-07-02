#pragma once

class RuleEngine;
class PacketProcessor;
class TrafficMonitor;
class FileLogger;
class MongoLogger;
class PacketSimulator;
struct FirewallStats;
class Stack;
class Queue;

#include "imgui.h"
#include "implot.h"

class DashboardPanel;
class RulesPanel;
class BlacklistPanel;
class TrafficPanel;
class ThreatsPanel;
class LogsPanel;
class SettingsPanel;
#include "TerminalPanel.h"

#include <string>
#include <vector>
#include <ctime>

struct GLFWwindow;

struct Notification {
    std::string title;
    std::string message;
    ImVec4 color;
    double timestamp;
};

class FirewallGUI {
public:
    FirewallGUI(RuleEngine* e, PacketProcessor* p, TrafficMonitor* m, FileLogger* fl, MongoLogger* ml,
                FirewallStats* s, Stack* st, Queue* q, PacketSimulator* sim);
    ~FirewallGUI();

    bool Init();
    void Run();
    void Shutdown();

    void AddNotification(const std::string& title, const std::string& msg, ImVec4 color);

    DashboardPanel* dashboardPanel_;
    RulesPanel* rulesPanel_;
    BlacklistPanel* blacklistPanel_;
    TrafficPanel* trafficPanel_;
    ThreatsPanel* threatsPanel_;
    LogsPanel* logsPanel_;
    SettingsPanel* settingsPanel_;
    TerminalPanel* terminalPanel_;

    RuleEngine* engine_;
    PacketProcessor* processor_;
    TrafficMonitor* monitor_;
    FileLogger* fileLogger_;
    MongoLogger* mongoLogger_;
    FirewallStats* stats_;
    Stack* history_;
    Queue* queue_;
    PacketSimulator* simulator_;

    std::vector<Notification> notifications_;
    bool notificationOpen_ = false;
    int notificationCount_ = 0;
    float uiFontScale_ = 1.0f;

    ImFont* uiFont_ = nullptr;
    ImFont* monoFont_ = nullptr;
    GLFWwindow* window_ = nullptr;

    static constexpr float kLeftSidebarW = 72.0f;
    static constexpr float kRightSidebarW = 280.0f;
    static constexpr float kTopBarH = 56.0f;

private:
    void Render();
    void RenderLeftSidebar();
    void RenderTopBar();
    void RenderRightSidebar();
    void RenderNotifications();
    void ApplyTheme();

    int activePage_ = 0;
    bool terminalOpen_ = false;
    bool terminalMaximized_ = false;
    int threatNotificationCount_ = 0;
    float terminalAnimHeight_ = 0.0f;
    float terminalAnimStartHeight_ = 0.0f;
    float terminalAnimTargetHeight_ = 0.0f;
    double terminalAnimStartTime_ = 0.0;
    bool rightSidebarOpen_ = true;
    char searchBuffer_[256] = {};
    double lastUpdateTime_ = 0.0;

    std::time_t appStartTime_;
    double lastSysInfoTime_ = 0.0;
    float cpuUsage_ = 0.0f;
    float memUsageMB_ = 0.0f;
};
