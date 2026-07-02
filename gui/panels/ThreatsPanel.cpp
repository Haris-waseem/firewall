#include "ThreatsPanel.h"
#include "../../include/ImGuiColors.h"
#include <string>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

void ThreatsPanel::SyncThreats(FirewallStats* stats) {
    if (!stats) return;
    threats_ = stats->detectedThreats;
}

void ThreatsPanel::Render() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();

    int total = (int)threats_.size();
    int critical = 0, warning = 0, info = 0;
    for (const auto& t : threats_) {
        if (t.severity == 1) critical++;
        else if (t.severity == 2) warning++;
        else info++;
    }

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Threat Alerts");
    std::string st = std::to_string(total) + " total, " + std::to_string(critical) + " critical";
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), st.c_str());

    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 120, startY + 4));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1, 0.09f, 0.267f, 0.1f));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
    if (ImGui::Button("Clear All", ImVec2(90, 30))) {
        threats_.clear();
        if (stats_) {
            stats_->detectedThreats.clear();
            stats_->threatsDetected = 0;
            stats_->criticalThreats = 0;
        }
    }
    ImGui::PopStyleColor(2);

    float chipY = startY + 56;
    struct FilterChip { const char* label; int count; int id; ImU32 color; };
    FilterChip chips[] = {
        {"All", total, 0, C(COL_CYAN)},
        {"Critical", critical, 1, C(COL_RED)},
        {"Warning", warning, 2, C(COL_AMBER)},
        {"Info", info, 3, C(COL_TEXT_DIM)}
    };

    ImGui::SetCursorPos(ImVec2(24, chipY));
    float chipX = 0;
    for (int i = 0; i < 4; ++i) {
        bool active = (filterTab_ == chips[i].id);
        ImU32 chipBg = active ? chips[i].color : C(COL_BG_INPUT);
        ImU32 chipText = active ? C(ImVec4(1,1,1,1)) : C(COL_TEXT_MUTED);
        std::string label = std::string(chips[i].label) + " (" + std::to_string(chips[i].count) + ")";

        ImVec2 textSize = ImGui::CalcTextSize(label.c_str());
        float chipW = textSize.x + 24;

        ImVec2 cPos = ImVec2(wPos.x + 24 + chipX, wPos.y + chipY);
        if (active) {
            dl->AddRectFilled(cPos, ImVec2(cPos.x + chipW, cPos.y + 32), chipBg, 16.0f);
        } else {
            dl->AddRectFilled(cPos, ImVec2(cPos.x + chipW, cPos.y + 32), chipBg, 16.0f);
            dl->AddRect(cPos, ImVec2(cPos.x + chipW, cPos.y + 32), C(COL_BORDER_CARD), 16.0f);
        }
        dl->AddText(ImVec2(cPos.x + 12, cPos.y + 8), chipText, label.c_str());

        ImGui::SetCursorPos(ImVec2(24 + chipX, chipY));
        ImGui::InvisibleButton(("##chip" + std::to_string(i)).c_str(), ImVec2(chipW, 32));
        if (ImGui::IsItemClicked()) filterTab_ = chips[i].id;
        chipX += chipW + 8;
    }

    float listY = chipY + 48;
    ImGui::SetCursorPos(ImVec2(24, listY));
    float listH = ImGui::GetContentRegionAvail().y - 60;
    ImGui::BeginChild("##ThreatList", ImVec2(ImGui::GetContentRegionAvail().x - 24, listH), false);

    if (threats_.empty()) {
        ImGui::SetCursorPos(ImVec2(10, 10));
        ImGui::TextColored(COL_TEXT_MUTED, "No threats detected. System is secure.");
    } else {
        for (int i = (int)threats_.size() - 1; i >= 0; --i) {
            const auto& t = threats_[i];
            if (filterTab_ != 0 && t.severity != filterTab_) continue;

            float cardY = ImGui::GetCursorPosY();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
            ImGui::BeginChild((std::string("ThreatCard") + std::to_string(i)).c_str(), ImVec2(ImGui::GetContentRegionAvail().x, 88), true);

            ImVec2 cMin = ImGui::GetWindowPos();
            ImVec2 cMax = ImVec2(cMin.x + ImGui::GetWindowWidth(), cMin.y + ImGui::GetWindowHeight());

            ImU32 sevColor = (t.severity == 1) ? C(COL_RED) : ((t.severity == 2) ? C(COL_AMBER) : C(COL_TEXT_DIM));
            ImU32 sevBg = (t.severity == 1) ? IM_COL32(255, 23, 68, 25) : ((t.severity == 2) ? IM_COL32(255, 171, 0, 25) : IM_COL32(68, 68, 102, 25));

            dl->AddRectFilled(ImVec2(cMin.x, cMin.y), ImVec2(cMin.x + 4, cMax.y), sevColor);

            const char* sevLabel = t.severity == 1 ? "CRITICAL" : (t.severity == 2 ? "WARNING" : "INFO");
            ImVec2 sevTextSz = ImGui::CalcTextSize(sevLabel);
            dl->AddRectFilled(ImVec2(cMin.x + 16, cMin.y + 12),
                ImVec2(cMin.x + 16 + sevTextSz.x + 12, cMin.y + 26),
                sevBg, 3.0f);
            dl->AddRect(ImVec2(cMin.x + 16, cMin.y + 12),
                ImVec2(cMin.x + 16 + sevTextSz.x + 12, cMin.y + 26),
                sevColor, 3.0f);
            dl->AddText(ImVec2(cMin.x + 22, cMin.y + 14), sevColor, sevLabel);

            dl->AddText(ImVec2(cMin.x + 160, cMin.y + 14), C(COL_TEXT), t.threatType.c_str());
            dl->AddText(ImVec2(cMin.x + 16, cMin.y + 38), C(COL_TEXT_MUTED),
                ("Source: " + t.sourceIP + " | " + t.details).c_str());

            float btnX = cMax.x - 180;
            ImGui::SetCursorPos(ImVec2(btnX - cMin.x + ImGui::GetWindowPos().x - wPos.x, 28));
            ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(255, 23, 68, 25));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
            if (ImGui::Button(("Block IP##" + std::to_string(i)).c_str(), ImVec2(80, 28))) {
                if (engine_) engine_->addToBlacklist(t.sourceIP);
            }
            ImGui::PopStyleColor(2);
            ImGui::SameLine();
            if (ImGui::Button(("Dismiss##" + std::to_string(i)).c_str(), ImVec2(70, 28))) {
                threats_.erase(threats_.begin() + i);
                i--;
            }

            dl->AddText(ImVec2(cMin.x + 16, cMax.y - 22), C(COL_TEXT_DIM), t.timestamp.c_str());

            ImGui::EndChild();
            ImGui::PopStyleColor(2);
            ImGui::PopStyleVar(2);

            ImGui::SetCursorPosY(cardY + 96);
        }
    }

    ImGui::EndChild();
}
