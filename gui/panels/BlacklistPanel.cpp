#include "BlacklistPanel.h"
#include "../../include/ImGuiColors.h"
#include "../../include/IconsFontAwesome.h"
#include <string>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

void BlacklistPanel::Render() {
    if (!engine_) return;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Blacklist / Whitelist");
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), "Manage blocked and trusted IP addresses");

    float toggleY = startY + 56;
    float toggleW = 320.0f;
    float toggleH = 38.0f;
    float halfW = toggleW * 0.5f;

    dl->AddRectFilled(
        ImVec2(wPos.x + 24, wPos.y + toggleY),
        ImVec2(wPos.x + 24 + toggleW, wPos.y + toggleY + toggleH),
        C(COL_BG_INPUT), 10.0f);

    if (selectedTab_ == 0) {
        dl->AddRect(
            ImVec2(wPos.x + 24, wPos.y + toggleY),
            ImVec2(wPos.x + 24 + toggleW, wPos.y + toggleY + toggleH),
            C(COL_RED), 10.0f, 0, 1.5f);
        dl->AddRectFilled(
            ImVec2(wPos.x + 28, wPos.y + toggleY + 4),
            ImVec2(wPos.x + 24 + halfW - 4, wPos.y + toggleY + toggleH - 4),
            IM_COL32(255, 23, 68, 25), 8.0f);
    } else {
        dl->AddRect(
            ImVec2(wPos.x + 24, wPos.y + toggleY),
            ImVec2(wPos.x + 24 + toggleW, wPos.y + toggleY + toggleH),
            C(COL_GREEN), 10.0f, 0, 1.5f);
        dl->AddRectFilled(
            ImVec2(wPos.x + 28 + halfW, wPos.y + toggleY + 4),
            ImVec2(wPos.x + 24 + toggleW - 4, wPos.y + toggleY + toggleH - 4),
            IM_COL32(0, 230, 118, 25), 8.0f);
    }

    ImU32 blkTxt = selectedTab_ == 0 ? C(COL_RED) : C(COL_TEXT_MUTED);
    ImU32 whtTxt = selectedTab_ == 1 ? C(COL_GREEN) : C(COL_TEXT_MUTED);
    dl->AddText(
        ImVec2(wPos.x + 24 + halfW * 0.5f - 32, wPos.y + toggleY + 10),
        blkTxt, "Blacklist");
    dl->AddText(
        ImVec2(wPos.x + 24 + halfW + halfW * 0.5f - 30, wPos.y + toggleY + 10),
        whtTxt, "Whitelist");

    ImGui::SetCursorPos(ImVec2(24, toggleY));
    ImGui::InvisibleButton("##blkTab", ImVec2(halfW, toggleH));
    if (ImGui::IsItemClicked()) selectedTab_ = 0;
    ImGui::SameLine(0, 0);
    ImGui::InvisibleButton("##whtTab", ImVec2(halfW, toggleH));
    if (ImGui::IsItemClicked()) selectedTab_ = 1;

    float inputY = toggleY + toggleH + 16;

    ImGui::SetCursorPos(ImVec2(24, inputY));
    ImGui::PushItemWidth(420);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, C(COL_BG_INPUT));
    ImGui::PushStyleColor(ImGuiCol_Border, C(COL_BORDER_CARD));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::InputTextWithHint("##newIP",
        selectedTab_ == 0 ? "Enter IP address e.g. 192.168.1.1" : "Enter IP address to whitelist",
        newIP_, 64);
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::PopItemWidth();

    ImGui::SameLine(0, 8);
    if (selectedTab_ == 0) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 0.09f, 0.267f, 0.1f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 0.09f, 0.267f, 0.2f));
        ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
        ImVec4 redBorder = ImVec4(1, 0.09f, 0.267f, 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Border, redBorder);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0, 0.902f, 0.463f, 0.1f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0.902f, 0.463f, 0.2f));
        ImGui::PushStyleColor(ImGuiCol_Text, COL_GREEN);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
        ImVec4 grnBorder = ImVec4(0, 0.902f, 0.463f, 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Border, grnBorder);
    }
    const char* btnLabel = selectedTab_ == 0 ? (std::string(ICON_FA_BAN) + " Block IP").c_str()
                                             : (std::string(ICON_FA_CHECK) + " Trust IP").c_str();
    if (ImGui::Button(btnLabel, ImVec2(140, 32))) {
        if (newIP_[0] != '\0') {
            if (selectedTab_ == 0) engine_->addToBlacklist(newIP_);
            else engine_->addToWhitelist(newIP_);
            newIP_[0] = '\0';
        }
    }
    ImGui::PopStyleColor(5);
    ImGui::PopStyleVar(2);

    float listY = inputY + 52;
    ImGui::SetCursorPos(ImVec2(24, listY));
    float listH = ImGui::GetContentRegionAvail().y - 20;
    ImGui::BeginChild("##IPList", ImVec2(ImGui::GetContentRegionAvail().x - 24, listH), false);

    std::vector<std::string> ips;
    bool isBlacklist;

    if (selectedTab_ == 0) {
        ips = engine_->getBlacklistIPs();
        isBlacklist = true;
    } else {
        ips = engine_->getWhitelistIPs();
        isBlacklist = false;
    }

    if (ips.empty()) {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 40);
        ImVec2 txtSz = ImGui::CalcTextSize("No IPs in this list.");
        ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - txtSz.x) * 0.5f);
        ImGui::TextColored(COL_TEXT_MUTED, "No IPs in this list.");
        ImGui::EndChild();
        return;
    }

    ImDrawList* childDl = ImGui::GetWindowDrawList();
    ImVec2 childWinPos = ImGui::GetWindowPos();
    float childW = ImGui::GetContentRegionAvail().x;

    float cardGap = 12.0f;
    float cardW = (childW - cardGap) * 0.5f;
    float cardH = 72.0f;

    int cols = 2;
    for (size_t i = 0; i < ips.size(); ++i) {
        int col = (int)i % cols;
        int row = (int)i / cols;

        float cardX = col * (cardW + cardGap);
        float cardY = row * (cardH + cardGap);

        ImGui::SetCursorPos(ImVec2(cardX, cardY));
        ImGui::PushID((int)i);

        ImGui::PushStyleColor(ImGuiCol_ChildBg, C(COL_BG_CARD));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Border, C(COL_BORDER_CARD));
        ImGui::BeginChild(("IPCard" + std::to_string(i)).c_str(), ImVec2(cardW, cardH), true);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        ImVec2 cMin = ImGui::GetWindowPos();
        ImVec2 cMax = ImVec2(cMin.x + ImGui::GetWindowWidth(), cMin.y + ImGui::GetWindowHeight());

        if (isBlacklist) {
            ImU32 iconBg = IM_COL32(255, 23, 68, 30);
            ImU32 iconFg = IM_COL32(255, 23, 68, 255);
            childDl->AddRectFilled(
                ImVec2(cMin.x + 14, cMin.y + 14),
                ImVec2(cMin.x + 48, cMin.y + 48),
                iconBg, 8.0f);
            childDl->AddText(ImVec2(cMin.x + 22, cMin.y + 22), iconFg, ICON_FA_BAN);

            childDl->AddText(ImVec2(cMin.x + 56, cMin.y + 14),
                IM_COL32(255, 255, 255, 255), ips[i].c_str());
            childDl->AddText(ImVec2(cMin.x + 56, cMin.y + 36),
                IM_COL32(140, 145, 170, 255), "Blocked manually");

            float badgePad = 8.0f;
            ImVec2 badgeTxtSize = ImGui::CalcTextSize("BLACKLISTED");
            float badgeW = badgeTxtSize.x + badgePad * 2;
            float badgeH = 20.0f;
            float badgeX = cMax.x - badgeW - 40;
            float badgeY = cMin.y + 14;
            childDl->AddRect(
                ImVec2(badgeX, badgeY),
                ImVec2(badgeX + badgeW, badgeY + badgeH),
                IM_COL32(255, 23, 68, 120), badgeH * 0.5f, 0, 1.0f);
            childDl->AddText(
                ImVec2(badgeX + badgePad, badgeY + 3),
                IM_COL32(255, 23, 68, 255), "BLACKLISTED");

            ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 30, 24));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.65f, 1.0f));
            if (ImGui::SmallButton(("##del" + std::to_string(i)).c_str())) {
                engine_->removeFromBlacklist(ips[i]);
            }
            ImVec2 btnMin = ImVec2(cMin.x + ImGui::GetWindowWidth() - 30, cMin.y + 24);
            ImVec2 btnMax = ImVec2(btnMin.x + 20, btnMin.y + 20);
            childDl->AddText(ImVec2(btnMin.x + 2, btnMin.y + 2),
                IM_COL32(140, 145, 170, 200), ICON_FA_TRASH_O);
            ImGui::PopStyleColor();
        } else {
            ImU32 iconBg = IM_COL32(0, 230, 118, 30);
            ImU32 iconFg = IM_COL32(0, 230, 118, 255);
            childDl->AddRectFilled(
                ImVec2(cMin.x + 14, cMin.y + 14),
                ImVec2(cMin.x + 48, cMin.y + 48),
                iconBg, 8.0f);
            childDl->AddText(ImVec2(cMin.x + 22, cMin.y + 22), iconFg, ICON_FA_SHIELD);

            childDl->AddText(ImVec2(cMin.x + 56, cMin.y + 14),
                IM_COL32(255, 255, 255, 255), ips[i].c_str());
            childDl->AddText(ImVec2(cMin.x + 56, cMin.y + 36),
                IM_COL32(140, 145, 170, 255), "Trusted gateway");

            float badgePad = 8.0f;
            ImVec2 badgeTxtSize = ImGui::CalcTextSize("WHITELISTED");
            float badgeW = badgeTxtSize.x + badgePad * 2;
            float badgeH = 20.0f;
            float badgeX = cMax.x - badgeW - 40;
            float badgeY = cMin.y + 14;
            childDl->AddRect(
                ImVec2(badgeX, badgeY),
                ImVec2(badgeX + badgeW, badgeY + badgeH),
                IM_COL32(0, 230, 118, 120), badgeH * 0.5f, 0, 1.0f);
            childDl->AddText(
                ImVec2(badgeX + badgePad, badgeY + 3),
                IM_COL32(0, 230, 118, 255), "WHITELISTED");

            ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 30, 24));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.65f, 1.0f));
            if (ImGui::SmallButton(("##del" + std::to_string(i)).c_str())) {
                engine_->removeFromWhitelist(ips[i]);
            }
            ImVec2 btnMin = ImVec2(cMin.x + ImGui::GetWindowWidth() - 30, cMin.y + 24);
            childDl->AddText(ImVec2(btnMin.x + 2, btnMin.y + 2),
                IM_COL32(140, 145, 170, 200), ICON_FA_TRASH_O);
            ImGui::PopStyleColor();
        }

        ImGui::EndChild();
        ImGui::PopID();
    }

    int totalRows = ((int)ips.size() + 1) / 2;
    float totalH = totalRows * (cardH + cardGap);
    ImGui::SetCursorPosY(totalH);

    ImGui::EndChild();
}
