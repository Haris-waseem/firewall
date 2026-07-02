#include "RulesPanel.h"
#include "../../include/ImGuiColors.h"
#include <string>
#include <sstream>
#include <algorithm>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

void RulesPanel::Render() {
    auto rules = engine_->getAllRules();
    int total = (int)rules.size();
    int allowCount = 0, blockCount = 0;
    for (const auto& r : rules) {
        if (r.action == Action::ALLOW) allowCount++;
        else blockCount++;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Firewall Rules");
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), "Manage packet filtering rules");

    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 160, startY + 4));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0.831f, 1.0f, 0.1f));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_CYAN);
    if (ImGui::Button("+ Add New Rule", ImVec2(140, 36))) {
        showAddPopup_ = true;
    }
    ImGui::PopStyleColor(2);

    ImGui::SetCursorPos(ImVec2(24, startY + 52));
    ImVec2 chipPos = ImVec2(wPos.x + 24, wPos.y + startY + 52);

    ImU32 chipBg = IM_COL32(26, 26, 46, 255);
    ImU32 chipBorder = IM_COL32(42, 42, 74, 255);

    dl->AddRectFilled(chipPos, ImVec2(chipPos.x + 110, chipPos.y + 28), chipBg, 14.0f);
    dl->AddRect(chipPos, ImVec2(chipPos.x + 110, chipPos.y + 28), chipBorder, 14.0f);
    std::string tStr = "Total: " + std::to_string(total);
    dl->AddText(ImVec2(chipPos.x + 12, chipPos.y + 6), C(COL_TEXT), tStr.c_str());

    dl->AddRectFilled(ImVec2(chipPos.x + 120, chipPos.y), ImVec2(chipPos.x + 230, chipPos.y + 28), chipBg, 14.0f);
    dl->AddRect(ImVec2(chipPos.x + 120, chipPos.y), ImVec2(chipPos.x + 230, chipPos.y + 28), chipBorder, 14.0f);
    std::string aStr = "Allow: " + std::to_string(allowCount);
    dl->AddText(ImVec2(chipPos.x + 132, chipPos.y + 6), C(COL_GREEN), aStr.c_str());

    dl->AddRectFilled(ImVec2(chipPos.x + 240, chipPos.y), ImVec2(chipPos.x + 350, chipPos.y + 28), chipBg, 14.0f);
    dl->AddRect(ImVec2(chipPos.x + 240, chipPos.y), ImVec2(chipPos.x + 350, chipPos.y + 28), chipBorder, 14.0f);
    std::string bStr = "Block: " + std::to_string(blockCount);
    dl->AddText(ImVec2(chipPos.x + 252, chipPos.y + 6), C(COL_RED), bStr.c_str());

    ImGui::SetCursorPos(ImVec2(24, startY + 92));
    float tableH = ImGui::GetContentRegionAvail().y - 100;
    ImGui::BeginChild("##RulesTableContainer", ImVec2(ImGui::GetContentRegionAvail().x - 24, tableH), false);

    if (ImGui::BeginTable("RulesTable", 9,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Source IP", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("Dest Port", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Priority", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Created", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Controls", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& r : rules) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            bool en = r.enabled;
            if (ImGui::SmallButton(en ? "ON" : "OFF")) {
                if (en) engine_->disableRule(r.ruleID);
                else engine_->enableRule(r.ruleID);
            }

            ImGui::TableNextColumn();
            std::string rid = "R-" + std::to_string(r.ruleID);
            ImGui::Text("%s", rid.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", protocolToStr(r.protocol).c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", r.sourceIP.c_str());

            ImGui::TableNextColumn();
            if (r.destPort > 0) ImGui::Text("%d", r.destPort);
            else ImGui::TextColored(COL_TEXT_MUTED, "Any");

            ImGui::TableNextColumn();
            if (r.action == Action::ALLOW)
                ImGui::TextColored(COL_GREEN, "ALLOW");
            else
                ImGui::TextColored(COL_RED, "BLOCK");

            ImGui::TableNextColumn();
            ImGui::Text("%d", r.priority);

            ImGui::TableNextColumn();
            ImGui::TextColored(COL_TEXT_DIM, "2024-01-15");

            ImGui::TableNextColumn();
            if (ImGui::SmallButton(("E##" + std::to_string(r.ruleID)).c_str())) {
                editRuleID_ = r.ruleID;
                editAction_ = (r.action == Action::ALLOW) ? 0 : 1;
                editProtocol_ = (r.protocol == Protocol::TCP) ? 0 : ((r.protocol == Protocol::UDP) ? 1 : 2);
                strncpy_s(editSrcIP_, sizeof(editSrcIP_), r.sourceIP.c_str(), _TRUNCATE);
                editDestPort_ = r.destPort;
                editPriority_ = r.priority;
                showEditPopup_ = true;
            }
            ImGui::SameLine();
            if (ImGui::SmallButton(("D##" + std::to_string(r.ruleID)).c_str())) {
                deleteRuleID_ = r.ruleID;
                showDeleteConfirm_ = true;
            }
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();

    if (showDeleteConfirm_) {
        ImGui::OpenPopup("Confirm Delete");
        ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        if (ImGui::BeginPopupModal("Confirm Delete", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("Are you sure you want to delete rule #%d?", deleteRuleID_);
            ImGui::Separator();
            if (ImGui::Button("Yes", ImVec2(80, 0))) {
                if (engine_) engine_->removeRule(deleteRuleID_);
                showDeleteConfirm_ = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("No", ImVec2(80, 0))) {
                showDeleteConfirm_ = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    if (showAddPopup_) {
        ImGui::OpenPopup("Add New Rule");
        RenderAddRulePopup();
    }

    if (showEditPopup_) {
        ImGui::OpenPopup("Edit Rule");
        RenderEditRulePopup();
    }
}

void RulesPanel::RenderAddRulePopup() {
    ImGui::SetNextWindowSize(ImVec2(480, 420), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    ImGui::PushStyleColor(ImGuiCol_PopupBg, COL_BG_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 16.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);

    if (ImGui::BeginPopupModal("Add New Rule", &showAddPopup_,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Add New Rule");
        ImGui::Separator();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Action");
        ImGui::SameLine(120);
        if (ImGui::Button(newAction_ == 0 ? "ALLOW" : "Allow", ImVec2(100, 30))) newAction_ = 0;
        ImGui::SameLine();
        if (ImGui::Button(newAction_ == 1 ? "BLOCK" : "Block", ImVec2(100, 30))) newAction_ = 1;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Protocol");
        ImGui::SameLine(120);
        if (ImGui::Button(newProtocol_ == 0 ? "TCP" : "Tcp", ImVec2(80, 30))) newProtocol_ = 0;
        ImGui::SameLine();
        if (ImGui::Button(newProtocol_ == 1 ? "UDP" : "Udp", ImVec2(80, 30))) newProtocol_ = 1;
        ImGui::SameLine();
        if (ImGui::Button(newProtocol_ == 2 ? "ICMP" : "Icmp", ImVec2(80, 30))) newProtocol_ = 2;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Source IP");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(250);
        ImGui::InputText("##srcIp", newSrcIP_, 64);
        ImGui::PopItemWidth();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        ImGui::Text("Dest Port");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(100);
        ImGui::InputInt("##dstPort", &newDestPort_);
        ImGui::PopItemWidth();
        if (newDestPort_ < 0) newDestPort_ = 0;
        if (newDestPort_ > 65535) newDestPort_ = 65535;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        ImGui::Text("Priority");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(100);
        ImGui::InputInt("##priority", &newPriority_);
        ImGui::PopItemWidth();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 20);
        ImGui::Separator();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);

        float btnAreaY = ImGui::GetCursorPosY();
        float winW = ImGui::GetWindowWidth();
        ImGui::SetCursorPos(ImVec2(winW * 0.5f - 200, btnAreaY));
        if (ImGui::Button("Cancel", ImVec2(180, 36))) {
            showAddPopup_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Add Rule", ImVec2(180, 36))) {
            if (engine_) {
                Rule r;
                r.action = (newAction_ == 0) ? Action::ALLOW : Action::BLOCK;
                r.protocol = (newProtocol_ == 0) ? Protocol::TCP : (newProtocol_ == 1 ? Protocol::UDP : Protocol::ICMP);
                r.sourceIP = newSrcIP_;
                r.destPort = newDestPort_;
                r.direction = Direction::INBOUND;
                r.priority = newPriority_;
                engine_->addRule(r);
                showAddPopup_ = false;
                newSrcIP_[0] = '\0';
            }
        }

        ImGui::EndPopup();
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void RulesPanel::RenderEditRulePopup() {
    ImGui::SetNextWindowSize(ImVec2(480, 420), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    ImGui::PushStyleColor(ImGuiCol_PopupBg, COL_BG_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 16.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);

    if (ImGui::BeginPopupModal("Edit Rule", &showEditPopup_,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Edit Rule #%d", editRuleID_);
        ImGui::Separator();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Action");
        ImGui::SameLine(120);
        if (ImGui::Button(editAction_ == 0 ? "ALLOW" : "Allow", ImVec2(100, 30))) editAction_ = 0;
        ImGui::SameLine();
        if (ImGui::Button(editAction_ == 1 ? "BLOCK" : "Block", ImVec2(100, 30))) editAction_ = 1;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Protocol");
        ImGui::SameLine(120);
        if (ImGui::Button(editProtocol_ == 0 ? "TCP" : "Tcp", ImVec2(80, 30))) editProtocol_ = 0;
        ImGui::SameLine();
        if (ImGui::Button(editProtocol_ == 1 ? "UDP" : "Udp", ImVec2(80, 30))) editProtocol_ = 1;
        ImGui::SameLine();
        if (ImGui::Button(editProtocol_ == 2 ? "ICMP" : "Icmp", ImVec2(80, 30))) editProtocol_ = 2;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        ImGui::Text("Source IP");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(250);
        ImGui::InputText("##editSrcIp", editSrcIP_, 64);
        ImGui::PopItemWidth();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        ImGui::Text("Dest Port");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(100);
        ImGui::InputInt("##editDstPort", &editDestPort_);
        ImGui::PopItemWidth();
        if (editDestPort_ < 0) editDestPort_ = 0;
        if (editDestPort_ > 65535) editDestPort_ = 65535;

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        ImGui::Text("Priority");
        ImGui::SameLine(120);
        ImGui::PushItemWidth(100);
        ImGui::InputInt("##editPriority", &editPriority_);
        ImGui::PopItemWidth();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 20);
        ImGui::Separator();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);

        float btnAreaY = ImGui::GetCursorPosY();
        float winW = ImGui::GetWindowWidth();
        ImGui::SetCursorPos(ImVec2(winW * 0.5f - 200, btnAreaY));
        if (ImGui::Button("Cancel", ImVec2(180, 36))) {
            showEditPopup_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Save", ImVec2(180, 36))) {
            if (engine_) {
                Action newAct = (editAction_ == 0) ? Action::ALLOW : Action::BLOCK;
                Protocol newProto = (editProtocol_ == 0) ? Protocol::TCP : ((editProtocol_ == 1) ? Protocol::UDP : Protocol::ICMP);
                engine_->updateRule(editRuleID_, newAct, editPriority_, Direction::INBOUND, newProto, editSrcIP_, editDestPort_);
                showEditPopup_ = false;
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::EndPopup();
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}
