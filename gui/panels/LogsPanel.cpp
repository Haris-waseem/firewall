#include "LogsPanel.h"
#include "../../include/ImGuiColors.h"
#include <string>
#include <fstream>
#include <algorithm>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

void LogsPanel::Render() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();
    float contentW = ImGui::GetContentRegionAvail().x;

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Logs");
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), "Full packet capture history");

    float controlsY = startY + 52;

    ImGui::SetCursorPos(ImVec2(24, controlsY));
    ImGui::PushItemWidth(400);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, COL_BG_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::InputTextWithHint("##SearchLogs", "Search by IP, port, rule ID...", searchBuf_, 256);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
    ImGui::PopItemWidth();

    ImGui::SameLine(0, 8);
    if (ImGui::Button("Search", ImVec2(80, 0))) { needsRefresh_ = true; }

    ImGui::SetCursorPos(ImVec2(24, controlsY + 36));
    ImGui::PushItemWidth(130);
    ImGui::Combo("##Protocol", &filterProtocol_, "All Protocols\0TCP\0UDP\0ICMP\0");
    ImGui::SameLine(0, 4);
    ImGui::Combo("##Action", &filterAction_, "All Actions\0ALLOW\0BLOCK\0");
    ImGui::SameLine(0, 4);
    ImGui::Combo("##Direction", &filterDirection_, "All\0Inbound\0Outbound\0");
    ImGui::PopItemWidth();

    if (needsRefresh_ && logger_) {
        std::string searchStr(searchBuf_);
        std::vector<std::string> raw;
        if (!searchStr.empty()) {
            raw = logger_->queryByIP(searchStr);
        } else {
            raw = logger_->readLastLines(100);
        }
        logLines_.clear();
        for (const auto& line : raw) {
            std::istringstream ss(line);
            std::vector<std::string> f;
            std::string tok;
            while (std::getline(ss, tok, ',')) f.push_back(tok);
            if (f.size() < 10) continue;
            if (filterProtocol_ != 0) {
                static const char* protoStrs[] = {"", "TCP", "UDP", "ICMP"};
                if (f[5] != protoStrs[filterProtocol_]) continue;
            }
            if (filterAction_ != 0) {
                static const char* actStrs[] = {"", "ALLOW", "BLOCK"};
                if (f[7] != actStrs[filterAction_]) continue;
            }
            if (filterDirection_ != 0) {
                static const char* dirStrs[] = {"", "INBOUND", "OUTBOUND"};
                if (f[6] != dirStrs[filterDirection_]) continue;
            }
            logLines_.push_back(line);
        }
        needsRefresh_ = false;
    }

    float exportX = ImGui::GetWindowWidth() - 140;
    ImGui::SetCursorPos(ImVec2(exportX, controlsY));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0.831f, 1.0f, 0.1f));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_CYAN);
    if (ImGui::Button("Export CSV", ImVec2(100, 30))) {
        if (logger_) {
                auto lines = logger_->readLastLines(100);
            std::ofstream out("firewall_export.csv");
            if (out.is_open()) {
                out << "Timestamp,PacketID,SourceIP,DestIP,"
                       "Port,Protocol,Direction,Action,"
                       "RuleID,Threat\n";
                for (const auto& line : lines) {
                    out << line << "\n";
                }
                out.close();
            }
        }
    }
    ImGui::PopStyleColor(2);

    std::string resultStr = "Showing " + std::to_string(logLines_.size()) + " packets";
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + controlsY + 72),
        C(COL_TEXT_MUTED), resultStr.c_str());

    float tableY = controlsY + 96;
    ImGui::SetCursorPos(ImVec2(24, tableY));
    float tableH = ImGui::GetContentRegionAvail().y - 50;
    ImGui::BeginChild("##LogTableContainer", ImVec2(contentW - 24, tableH), false);

    if (ImGui::BeginTable("LogsTable", 10,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Packet ID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Source IP", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Dest IP", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Dir", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Rule ID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Threat", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& line : logLines_) {
            size_t start = 0;
            size_t end = line.find(',');
            ImGui::TableNextRow();
            for (int col = 0; col < 10; ++col) {
                ImGui::TableNextColumn();
                std::string token = (end == std::string::npos) ? line.substr(start) : line.substr(start, end - start);
                ImGui::TextUnformatted(token.c_str());
                if (end != std::string::npos) {
                    start = end + 1;
                    end = line.find(',', start);
                }
            }
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();
}
