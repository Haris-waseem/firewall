#pragma once
#include "imgui.h"
#include <string>
#include <vector>

class RuleEngine;
class PacketProcessor;
class FileLogger;
class TrafficMonitor;
struct FirewallStats;
class Stack;
class PacketSimulator;

struct TerminalLine {
    std::string text;
    ImVec4 color;
};

class TerminalPanel {
public:
    TerminalPanel(RuleEngine* e, PacketProcessor* p, FileLogger* l, TrafficMonitor* m, FirewallStats* s, Stack* st, PacketSimulator* sim);
    void Render(float x, float y, float width, float height);
    void ProcessCommand(const std::string& cmd);
    void AddOutput(const std::string& text, ImVec4 color);
    void Clear();

    void SetOpenPtr(bool* ptr) { open_ = ptr; }
    void SetMaximizedPtr(bool* ptr) { maximized_ = ptr; }

    bool minimized_ = false;

private:
    bool* open_ = nullptr;
    bool* maximized_ = nullptr;

private:
    RuleEngine* engine_;
    PacketProcessor* processor_;
    FileLogger* logger_;
    TrafficMonitor* monitor_;
    FirewallStats* stats_;
    Stack* history_;
    PacketSimulator* simulator_;

    char inputBuffer_[256] = "";
    std::vector<TerminalLine> outputHistory_;
    bool scrollToBottom_ = false;
};
