#include "SettingsPanel.h"
#include "../../include/ImGuiColors.h"
#include "../../include/IconsFontAwesome.h"
#include <string>
#include <functional>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

static void RenderSection(const char* title, ImVec2 size, std::function<void()> content) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);

    ImGui::BeginChild(title, size, true);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 14), C(COL_TEXT), title);

    content();

    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

void SettingsPanel::Render() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();
    float contentW = ImGui::GetContentRegionAvail().x;

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Settings");
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), "Configure firewall behavior and connections");

    float halfW = (contentW - 56) * 0.5f;

    ImGui::SetCursorPos(ImVec2(24, startY + 56));

    // Column 1
    ImGui::BeginGroup();

    RenderSection("##FirewallSettings", ImVec2(halfW, 220), [&]() {
        ImGui::SetCursorPos(ImVec2(16, 40));
        ImGui::Checkbox("Enable Firewall", &firewallEnabled_);

        ImGui::SetCursorPos(ImVec2(16, 70));
        ImGui::Text("Default Action");
        ImGui::SameLine(140);
        if (ImGui::Button(defaultAction_ == 0 ? "ALLOW" : "Allow", ImVec2(80, 28))) defaultAction_ = 0;
        ImGui::SameLine();
        if (ImGui::Button(defaultAction_ == 1 ? "BLOCK" : "Block", ImVec2(80, 28))) defaultAction_ = 1;

        ImGui::SetCursorPos(ImVec2(16, 110));
        ImGui::Checkbox("Log All Packets", &logAll_);

        ImGui::SetCursorPos(ImVec2(16, 140));
        ImGui::Checkbox("Enable Threat Detection", &threatDetection_);
    });

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 16);

    RenderSection("##LogSettings", ImVec2(halfW, 160), [&]() {
        ImGui::SetCursorPos(ImVec2(16, 40));
        ImGui::Text("Log File Path");
        ImGui::SameLine(140);
        ImGui::TextColored(COL_TEXT_MUTED, "firewall.log");

        ImGui::SetCursorPos(ImVec2(16, 70));
        ImGui::Text("Max Log Size");
        ImGui::SameLine(140);
        ImGui::TextColored(COL_TEXT_MUTED, "10 MB");
    });

    ImGui::EndGroup();

    ImGui::SameLine(0, 16);

    // Column 2
    ImGui::BeginGroup();

    RenderSection("##MongoSettings", ImVec2(halfW, 220), [&]() {
        ImGui::SetCursorPos(ImVec2(16, 40));
        ImGui::Checkbox("Enable MongoDB Logging", &mongoEnabled_);

        ImGui::SetCursorPos(ImVec2(16, 70));
        ImGui::Text("Connection String");
        ImGui::SetCursorPos(ImVec2(16, 88));
        ImGui::PushItemWidth(halfW - 32);
        ImGui::InputText("##mongoURI", mongoURI_, 256);
        ImGui::PopItemWidth();

        ImGui::SetCursorPos(ImVec2(16, 120));
        ImGui::Text("Database");
        ImGui::SetCursorPos(ImVec2(16, 138));
        ImGui::PushItemWidth(halfW - 32);
        ImGui::InputText("##mongoDb", mongoDb_, 128);
        ImGui::PopItemWidth();

        ImGui::SetCursorPos(ImVec2(16, 170));

        if (ImGui::Button("Test Connection", ImVec2(halfW - 32, 0))) {
            if (mongoLogger_) mongoConnected_ = mongoLogger_->connect(mongoURI_);
            else mongoConnected_ = false;
        }
        ImGui::SameLine();
        if (mongoConnected_)
            ImGui::TextColored(COL_GREEN, "Connected successfully!");
        else
            ImGui::TextColored(COL_RED, "Failed to connect");
    });

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 16);

    RenderSection("##AboutSection", ImVec2(halfW, 160), [&]() {
        struct AboutRow { const char* label; const char* value; };
        AboutRow rows[] = {
            {"Project", "Terminal - Network Firewall"},
            {"Version", "1.0.0"},
            {"Developer", "Haris"},
            {"University", "COMSATS University Islamabad"},
            {"Course", "Data Structures & Algorithms"},
            {"Build", "C++ / CMake / MinGW"}
        };
        ImGui::SetCursorPos(ImVec2(16, 40));
        for (int i = 0; i < 6; ++i) {
            ImGui::TextColored(COL_TEXT_MUTED, "%s", rows[i].label);
            ImGui::SameLine(140);
            ImGui::Text("%s", rows[i].value);
            if (i < 5)
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 3);
        }
    });

    ImGui::EndGroup();

    ImGui::SetCursorPos(ImVec2(contentW * 0.5f - 160, ImGui::GetCursorPosY() + 30));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0.831f, 1.0f, 0.1f));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_CYAN);
    if (ImGui::Button("Save Configuration", ImVec2(320, 44))) {
        if (logger_ && engine_) {
            logger_->saveRules(engine_->getAllRules(), engine_->getDefaultPolicy());
            logger_->saveBlacklist(engine_->getBlacklistIPs());
            logger_->saveWhitelist(engine_->getWhitelistIPs());
        }
        if (mongoLogger_) {
            mongoLogger_->saveRules(engine_->getAllRules());
            mongoLogger_->saveBlacklist(engine_->getBlacklistIPs());
            mongoLogger_->saveWhitelist(engine_->getWhitelistIPs());
        }
    }
    ImGui::PopStyleColor(2);
}
