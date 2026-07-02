#include "TerminalPanel.h"
#include "../include/RuleEngine.h"
#include "../include/PacketProcessor.h"
#include "../include/TrafficMonitor.h"
#include "../include/FileLogger.h"
#include "../include/FirewallStats.h"
#include "../include/Stack.h"
#include "../include/PacketSimulator.h"
#include "../include/enums.h"
#include "../include/ImGuiColors.h"
#include <sstream>
#include <iostream>
#include <string>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

TerminalPanel::TerminalPanel(RuleEngine* e, PacketProcessor* p, FileLogger* l, TrafficMonitor* m, FirewallStats* s, Stack* st, PacketSimulator* sim)
    : engine_(e), processor_(p), logger_(l), monitor_(m), stats_(s), history_(st), simulator_(sim) {
    AddOutput("Firewall Terminal v1.0", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    AddOutput("Type 'help' for a list of commands.", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
}

void TerminalPanel::Render(float x, float y, float width, float height) {
    ImGui::SetNextWindowPos(ImVec2(x, y));
    ImGui::SetNextWindowSize(ImVec2(width, height));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollWithMouse;

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.035f, 0.035f, 0.07f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("TerminalOverlay", nullptr, flags);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();

    dl->AddRectFilled(
        ImVec2(wPos.x, wPos.y),
        ImVec2(wPos.x + width, wPos.y + height),
        IM_COL32(9, 9, 18, 255), 12.0f, ImDrawFlags_RoundCornersTop);

    dl->AddRectFilled(
        ImVec2(wPos.x, wPos.y + 36),
        ImVec2(wPos.x + width, wPos.y + 36 + 1),
        IM_COL32(30, 30, 58, 255));

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.059f, 0.059f, 0.118f, 1.0f));
    ImGui::BeginChild("TermHeader", ImVec2(width, 36), false);

    ImDrawList* headerDl = ImGui::GetWindowDrawList();
    ImVec2 headerPos = ImGui::GetWindowPos();

    float dotY = headerPos.y + 18.0f;

    headerDl->AddCircleFilled(ImVec2(headerPos.x + 20, dotY), 6.0f, IM_COL32(255, 95, 87, 255));
    ImGui::SetCursorPos(ImVec2(14, 10));
    ImGui::InvisibleButton("##close", ImVec2(12, 16));
    if (ImGui::IsItemClicked()) {
        if (open_) *open_ = false;
    }

    headerDl->AddCircleFilled(ImVec2(headerPos.x + 40, dotY), 6.0f, IM_COL32(254, 188, 46, 255));
    ImGui::SetCursorPos(ImVec2(34, 10));
    ImGui::InvisibleButton("##minimize", ImVec2(12, 16));
    if (ImGui::IsItemClicked()) {
        minimized_ = !minimized_;
    }

    headerDl->AddCircleFilled(ImVec2(headerPos.x + 60, dotY), 6.0f, IM_COL32(40, 200, 64, 255));
    ImGui::SetCursorPos(ImVec2(54, 10));
    ImGui::InvisibleButton("##maximize", ImVec2(12, 16));
    if (ImGui::IsItemClicked()) {
        if (maximized_) *maximized_ = !(*maximized_);
        minimized_ = false;
    }

    ImGui::SetCursorPos(ImVec2(80, 10));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.6f, 1.0f));
    ImGui::Text(">_ Firewall Terminal");
    ImGui::PopStyleColor();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    if (!minimized_) {
        float outputH = height - 36 - 36;
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.035f, 0.035f, 0.07f, 1.0f));
        ImGui::BeginChild("TermOutput", ImVec2(width, outputH), false, ImGuiWindowFlags_HorizontalScrollbar);

        for (const auto& line : outputHistory_) {
            ImGui::TextColored(line.color, "%s", line.text.c_str());
        }
        if (scrollToBottom_) {
            ImGui::SetScrollHereY(1.0f);
            scrollToBottom_ = false;
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();

        float inputY = height - 32;
        ImGui::SetCursorPos(ImVec2(12, inputY));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.6f, 1.0f));
        ImGui::Text("firewall@terminal:~$");
        ImGui::PopStyleColor();

        float promptW = ImGui::CalcTextSize("firewall@terminal:~$").x;
        ImGui::SameLine();
        ImGui::PushItemWidth(width - promptW - 36);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.878f, 0.878f, 1.0f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
        if (ImGui::InputText("##cmd", inputBuffer_, 256, ImGuiInputTextFlags_EnterReturnsTrue)) {
            std::string cmd(inputBuffer_);
            AddOutput("firewall@terminal:~$ " + cmd, ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
            ProcessCommand(cmd);
            inputBuffer_[0] = '\0';
            scrollToBottom_ = true;
        }
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(2);
        ImGui::PopItemWidth();
    }

    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

void TerminalPanel::ProcessCommand(const std::string& cmd) {
    if (cmd.empty()) return;

    std::istringstream iss(cmd);
    std::vector<std::string> args;
    std::string token;
    while (iss >> token) args.push_back(token);

    std::string c = args[0];

    if (c == "help") {
        AddOutput("Available commands: help, show-stats, list-rules, clear", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
        AddOutput("  block-ip <ip>, allow-ip <ip>, remove-block <ip>, remove-allow <ip>", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
        AddOutput("  show-blacklist, show-whitelist", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
        AddOutput("  add-rule <action> <dir> <proto> <ip> <port> [priority]", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
        AddOutput("  send-packet <srcIP> <dstPort> <proto> [dir] [isSYN]", ImVec4(0.533f, 0.533f, 0.667f, 1.0f));
    } else if (c == "show-stats") {
        AddOutput("Total Processed: " + std::to_string(stats_->totalProcessed), ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
        AddOutput("Total Blocked: " + std::to_string(stats_->totalBlocked), ImVec4(1.0f, 0.09f, 0.267f, 1.0f));
        AddOutput("Total Allowed: " + std::to_string(stats_->totalAllowed), ImVec4(0.0f, 0.902f, 0.463f, 1.0f));
    } else if (c == "clear") {
        Clear();
    } else if (c == "list-rules") {
        auto rules = engine_->getAllRules();
        for (const auto& r : rules) {
            AddOutput(r.toString(), r.action == Action::ALLOW ? ImVec4(0.0f, 0.902f, 0.463f, 1.0f) : ImVec4(1.0f, 0.09f, 0.267f, 1.0f));
        }
    } else if (c == "block-ip" && args.size() >= 2) {
        engine_->addToBlacklist(args[1]);
        AddOutput("IP " + args[1] + " added to blacklist.", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    } else if (c == "allow-ip" && args.size() >= 2) {
        engine_->addToWhitelist(args[1]);
        AddOutput("IP " + args[1] + " added to whitelist.", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    } else if (c == "remove-block" && args.size() >= 2) {
        engine_->removeFromBlacklist(args[1]);
        AddOutput("IP " + args[1] + " removed from blacklist.", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    } else if (c == "remove-allow" && args.size() >= 2) {
        engine_->removeFromWhitelist(args[1]);
        AddOutput("IP " + args[1] + " removed from whitelist.", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    } else if (c == "show-blacklist") {
        auto ips = engine_->getBlacklistIPs();
        AddOutput("Blacklisted IPs: " + std::to_string(ips.size()), ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
        for (const auto& ip : ips) AddOutput("  " + ip, ImVec4(1.0f, 0.09f, 0.267f, 1.0f));
    } else if (c == "show-whitelist") {
        auto ips = engine_->getWhitelistIPs();
        AddOutput("Whitelisted IPs: " + std::to_string(ips.size()), ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
        for (const auto& ip : ips) AddOutput("  " + ip, ImVec4(0.0f, 0.902f, 0.463f, 1.0f));
    } else if (c == "add-rule" && args.size() >= 6) {
        Rule r;
        r.action = strToAction(args[1]);
        r.direction = strToDirection(args[2]);
        r.protocol = strToProtocol(args[3]);
        r.sourceIP = args[4];
        r.destPort = std::stoi(args[5]);
        r.priority = (args.size() > 6) ? std::stoi(args[6]) : 100;
        engine_->addRule(r);
        AddOutput("Rule added.", ImVec4(0.0f, 0.902f, 0.463f, 1.0f));
    } else if (c == "send-packet" && args.size() >= 4) {
        Packet p;
        p.packetID = 9999;
        p.sourceIP = args[1];
        p.destIP = "192.168.1.100";
        p.destPort = std::stoi(args[2]);
        p.protocol = strToProtocol(args[3]);
        p.direction = (args.size() > 4) ? strToDirection(args[4]) : Direction::INBOUND;
        p.isSYN = (args.size() > 5) ? (args[5] == "true" || args[5] == "1") : false;
        p.payloadSize = 512;
        p.timestamp = Packet::currentTimestamp();
        processor_->process(p);
        AddOutput("Packet injected into processing pipeline.", ImVec4(0.0f, 0.831f, 1.0f, 1.0f));
    } else {
        AddOutput("Unknown command: " + c, ImVec4(1.0f, 0.09f, 0.267f, 1.0f));
    }
}

void TerminalPanel::AddOutput(const std::string& text, ImVec4 color) {
    outputHistory_.push_back({text, color});
    scrollToBottom_ = true;
}

void TerminalPanel::Clear() {
    outputHistory_.clear();
}
