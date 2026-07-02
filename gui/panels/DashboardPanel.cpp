#include "DashboardPanel.h"
#include "../../include/ImGuiColors.h"
#include "../../include/IconsFontAwesome.h"
#include <string>
#include <cmath>
#include <sstream>
#include <ctime>
#include <iomanip>

static std::string formatNumber(int n) {
    std::string s = std::to_string(n);
    int len = (int)s.size();
    for (int i = len - 3; i > 0; i -= 3)
        s.insert(s.begin() + i, ',');
    return s;
}
#include <fstream>

static ImU32 ColToU32(ImVec4 c) {
    return IM_COL32((int)(c.x*255), (int)(c.y*255), (int)(c.z*255), (int)(c.w*255));
}

DashboardPanel::DashboardPanel(FirewallStats* s, RuleEngine* e, PacketProcessor* p, TrafficMonitor* m, Stack* st, FileLogger* fl)
    : stats_(s), engine_(e), processor_(p), monitor_(m), history_(st), logger_(fl) {
}

void DashboardPanel::UpdateData() {
    if (!stats_) return;
    allowedBuffer_[bufferOffset_] = (float)(stats_->totalAllowed - lastAllowed_);
    blockedBuffer_[bufferOffset_] = (float)(stats_->totalBlocked - lastBlocked_);
    lastAllowed_ = stats_->totalAllowed;
    lastBlocked_ = stats_->totalBlocked;
    bufferOffset_ = (bufferOffset_ + 1) % 60;
}

static void HelpMarker(const char* desc) {
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void DashboardPanel::Render() {
    if (!stats_) return;

    float contentW = ImGui::GetContentRegionAvail().x;

    RenderStatCards();

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 16);
    ImGui::BeginChild("MiddleSection", ImVec2(contentW, 260), false);

    float chartW = contentW * 0.62f;
    float rulesW = contentW - chartW - 16;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);

    ImGui::BeginChild("TrafficChart", ImVec2(chartW, 250), true);
    RenderLiveTraffic();
    ImGui::EndChild();

    ImGui::PopStyleColor(1);

    ImGui::SameLine(0, 16);

    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::BeginChild("ActiveRules", ImVec2(rulesW, 250), true);
    RenderActiveRules();
    ImGui::EndChild();

    ImGui::PopStyleColor(1);
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(1);

    ImGui::EndChild();

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 16);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    float logH = ImGui::GetContentRegionAvail().y;
    ImGui::BeginChild("PacketLog", ImVec2(contentW, logH), true);
    RenderPacketLog();
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

void DashboardPanel::RenderStatCards() {
    float availWidth = ImGui::GetContentRegionAvail().x;
    float gap = 16.0f;
    float cardWidth = (availWidth - gap * 3) / 4.0f;
    float cardHeight = 110.0f;

    int total = stats_->totalProcessed;
    int allowed = stats_->totalAllowed;
    int blocked = stats_->totalBlocked;
    int threats = stats_->threatsDetected;
    int criticalThreats = stats_->criticalThreats;

    std::string trendProcessed = "\xe2\x86\x91 " + std::to_string(total) + " this session";
    std::string trendAllowed  = "\xe2\x86\x91 " + std::to_string(allowed) + " packets";
    std::string trendBlocked  = "\xe2\x86\x93 " + std::to_string(blocked) + " packets";
    std::string trendThreats  = "\xe2\x9a\xa0 " + std::to_string(criticalThreats) + " critical";

    struct StatCard {
        const char* label;
        int value;
        ImVec4 accentColor;
        ImVec4 valueColor;
        const char* trend;
        ImVec4 trendColor;
        const char* icon;
    };

    StatCard cards[] = {
        {"Total Processed",  total,   COL_CYAN,  COL_TEXT,  trendProcessed.c_str(), COL_CYAN,  ICON_FA_DATABASE},
        {"Packets Allowed",  allowed, COL_GREEN, COL_GREEN, trendAllowed.c_str(),   COL_GREEN, ICON_FA_CHECK_CIRCLE},
        {"Packets Blocked",  blocked, COL_RED,   COL_RED,   trendBlocked.c_str(),   COL_RED,   ICON_FA_BAN},
        {"Threats Detected", threats, COL_AMBER, COL_AMBER, trendThreats.c_str(),   COL_AMBER, ICON_FA_EXCLAMATION_TRIANGLE},
    };

    float startY = ImGui::GetCursorPosY();

    for (int i = 0; i < 4; ++i) {
        float x = i * (cardWidth + gap);
        ImGui::SetCursorPos(ImVec2(x, startY));

        ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
        ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
        ImGui::BeginChild(std::string("Card" + std::to_string(i)).c_str(), ImVec2(cardWidth, cardHeight), true);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        ImVec2 cMin = ImGui::GetWindowPos();
        ImVec2 cMax = ImVec2(cMin.x + ImGui::GetWindowWidth(), cMin.y + ImGui::GetWindowHeight());

        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImU32 accentU32 = ImColor(cards[i].accentColor);

        dl->AddRectFilled(
            ImVec2(cMin.x + 1, cMin.y + 6),
            ImVec2(cMin.x + 5, cMax.y - 6),
            accentU32, 2.0f
        );

        ImU32 iconBg = IM_COL32(
            (int)(cards[i].accentColor.x * 255),
            (int)(cards[i].accentColor.y * 255),
            (int)(cards[i].accentColor.z * 255),
            30
        );
        dl->AddRectFilled(
            ImVec2(cMin.x + 16, cMin.y + 14),
            ImVec2(cMin.x + 52, cMin.y + 50),
            iconBg, 8.0f
        );
        dl->AddText(
            ImVec2(cMin.x + 25, cMin.y + 21),
            accentU32,
            cards[i].icon
        );

        dl->AddText(
            ImVec2(cMin.x + 60, cMin.y + 18),
            ColToU32(COL_TEXT_MUTED),
            cards[i].label
        );

        std::string valStr = formatNumber(cards[i].value);
        dl->AddText(
            ImVec2(cMin.x + 60, cMin.y + 42),
            ColToU32(cards[i].valueColor),
            valStr.c_str()
        );

        ImVec2 trendSize = ImGui::CalcTextSize(cards[i].trend);
        dl->AddText(
            ImVec2(cMax.x - trendSize.x - 16, cMax.y - 24),
            ColToU32(cards[i].trendColor),
            cards[i].trend
        );

        ImGui::EndChild();
    }

    ImGui::SetCursorPosY(startY + cardHeight);
}

void DashboardPanel::RenderLiveTraffic() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float wW = ImGui::GetWindowWidth();

    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 12),
        IM_COL32(224, 224, 255, 255), "Live Packet Traffic");
    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 30),
        IM_COL32(107, 122, 154, 255), "Real-time allowed vs blocked");

    float legendX = wW - 210;
    dl->AddCircleFilled(ImVec2(wPos.x + legendX, wPos.y + 18), 4.0f, IM_COL32(0, 212, 255, 255));
    dl->AddText(ImVec2(wPos.x + legendX + 10, wPos.y + 12), IM_COL32(224, 224, 255, 255), "Allowed");
    dl->AddCircleFilled(ImVec2(wPos.x + legendX + 80, wPos.y + 18), 4.0f, IM_COL32(255, 51, 102, 255));
    dl->AddText(ImVec2(wPos.x + legendX + 90, wPos.y + 12), IM_COL32(224, 224, 255, 255), "Blocked");
    dl->AddText(ImVec2(wPos.x + legendX + 160, wPos.y + 12), IM_COL32(107, 122, 154, 255), "NOW");

    ImGui::SetCursorPos(ImVec2(0, 48));

    ImPlot::PushStyleColor(ImPlotCol_PlotBg, ImVec4(0.067f, 0.094f, 0.153f, 1.0f));
    ImPlot::PushStyleColor(ImPlotCol_AxisGrid, ImVec4(0.118f, 0.165f, 0.227f, 1.0f));
    ImPlot::PushStyleColor(ImPlotCol_AxisText, ImVec4(0.42f, 0.48f, 0.6f, 1.0f));

    if (ImPlot::BeginPlot("##LiveTraffic", ImVec2(-1, -1),
        ImPlotFlags_NoTitle | ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText)) {

        ImPlot::SetupAxes("", "",
            ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoGridLines,
            ImPlotAxisFlags_NoLabel);

        double yTicks[] = {0, 10, 20, 30, 40, 50};
        ImPlot::SetupAxisTicks(ImAxis_Y1, yTicks, 6, nullptr, true);
        double xTicks[] = {0, 10, 20, 30, 40, 50};
        ImPlot::SetupAxisTicks(ImAxis_X1, xTicks, 6, nullptr, true);

        ImPlot::SetupAxesLimits(0, 60, 0, 50, ImGuiCond_Always);

        ImPlotSpec allowedSpec;
        allowedSpec.LineColor = ImVec4(0.0f, 0.831f, 1.0f, 1.0f);
        allowedSpec.LineWeight = 2.0f;
        allowedSpec.FillColor = ImVec4(0.0f, 0.831f, 1.0f, 1.0f);
        allowedSpec.FillAlpha = 0.15f;
        ImPlot::PlotShaded("Allowed", allowedBuffer_, 60, 0.0, 1.0, 0.0, allowedSpec);

        ImPlotSpec blockedSpec;
        blockedSpec.LineColor = ImVec4(1.0f, 0.2f, 0.4f, 1.0f);
        blockedSpec.LineWeight = 2.0f;
        ImPlot::PlotLine("Blocked", blockedBuffer_, 60, 1.0, 0.0, blockedSpec);

        ImPlot::EndPlot();
    }

    ImPlot::PopStyleColor(3);
}

void DashboardPanel::RenderActiveRules() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();

    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 14),
        ColToU32(COL_TEXT), "Active Rules");

    auto rules = engine_->getAllRules();
    std::string countStr = std::to_string(rules.size()) + " rules loaded";
    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 32),
        ColToU32(COL_TEXT_MUTED), countStr.c_str());

    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 100, 16));
    if (ImGui::SmallButton("+ Add Rule")) { pendingNavigation_ = 1; }

    float yOff = 56.0f;
    ImGui::SetCursorPos(ImVec2(0, yOff));
    ImGui::BeginChild("##RulesList", ImVec2(0, 0), false);

    int count = 0;
    for (const auto& r : rules) {
        if (count >= 5) break;
        ImVec2 rowMin = ImVec2(wPos.x, wPos.y + yOff + (float)count * 34.0f);
        ImVec2 rowMax = ImVec2(rowMin.x + ImGui::GetWindowWidth(), rowMin.y + 34.0f);

        if (count % 2 == 1) {
            dl->AddRectFilled(rowMin, rowMax, IM_COL32(255, 255, 255, 5));
        }

        std::string idStr = "R-" + std::to_string(r.ruleID);
        ImGui::SetCursorPos(ImVec2(10, 8 + (float)count * 34.0f));
        dl->AddRectFilled(
            ImVec2(wPos.x + 10, wPos.y + yOff + (float)count * 34.0f + 6),
            ImVec2(wPos.x + 50, wPos.y + yOff + (float)count * 34.0f + 28),
            IM_COL32(30, 30, 58, 255), 4.0f);
        dl->AddText(
            ImVec2(wPos.x + 16, wPos.y + yOff + (float)count * 34.0f + 8),
            ColToU32(COL_TEXT_MUTED), idStr.c_str());

        std::string ruleText = protocolToStr(r.protocol) + " " + r.sourceIP + ":" + std::to_string(r.destPort);
        dl->AddText(
            ImVec2(wPos.x + 60, wPos.y + yOff + (float)count * 34.0f + 8),
            ColToU32(COL_TEXT), ruleText.c_str());

        float labelX = rowMax.x - 80.0f;
        ImU32 actBg = (r.action == Action::ALLOW) ? IM_COL32(0, 230, 118, 25) : IM_COL32(255, 23, 68, 25);
        ImU32 actText = (r.action == Action::ALLOW) ? ColToU32(COL_GREEN) : ColToU32(COL_RED);
        dl->AddRectFilled(
            ImVec2(labelX, rowMin.y + 6),
            ImVec2(labelX + 60, rowMin.y + 28),
            actBg, 4.0f);
        dl->AddText(
            ImVec2(labelX + 8, rowMin.y + 8),
            actText,
            (r.action == Action::ALLOW) ? "ALLOW" : "BLOCK");

        count++;
    }

    if (count == 0) {
        dl->AddText(ImVec2(wPos.x + 16, wPos.y + yOff + 10),
            ColToU32(COL_TEXT_MUTED), "No active rules.");
    }

    ImGui::EndChild();
}

void DashboardPanel::RenderPacketLog() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float wW = ImGui::GetWindowWidth();

    dl->AddText(ImVec2(wPos.x + 16, wPos.y + 16),
        ColToU32(COL_TEXT), "Recent Packet Log");

    float btnAreaX = wW - 280;
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(22, 22, 42, 255));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.25f, 0.25f, 0.40f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 0.75f, 0.85f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(22, 22, 42, 255));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(30, 30, 55, 255));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(18, 18, 36, 255));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.25f, 0.25f, 0.40f, 1.0f));

    ImGui::SetCursorPos(ImVec2(btnAreaX, 14));
    ImGui::PushID(101);
    dl->AddRectFilled(
        ImVec2(wPos.x + btnAreaX - 2, wPos.y + 12),
        ImVec2(wPos.x + btnAreaX + 110, wPos.y + 38),
        IM_COL32(22, 22, 42, 255), 6.0f);
    dl->AddRect(
        ImVec2(wPos.x + btnAreaX - 2, wPos.y + 12),
        ImVec2(wPos.x + btnAreaX + 110, wPos.y + 38),
        IM_COL32(64, 64, 102, 255), 6.0f, 0, 1.0f);
    dl->AddText(ImVec2(wPos.x + btnAreaX + 12, wPos.y + 17),
        ColToU32(COL_TEXT_MUTED), ICON_FA_FILTER);
    dl->AddText(ImVec2(wPos.x + btnAreaX + 30, wPos.y + 17),
        ColToU32(COL_TEXT_MUTED), "Filter (1)");
    ImGui::InvisibleButton("##FilterBtn", ImVec2(110, 26));
    if (ImGui::IsItemClicked()) filterOpen_ = !filterOpen_;
    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(btnAreaX + 120, 14));
    ImGui::PushID(102);
    dl->AddRectFilled(
        ImVec2(wPos.x + btnAreaX + 118, wPos.y + 12),
        ImVec2(wPos.x + btnAreaX + 220, wPos.y + 38),
        IM_COL32(22, 22, 42, 255), 6.0f);
    dl->AddRect(
        ImVec2(wPos.x + btnAreaX + 118, wPos.y + 12),
        ImVec2(wPos.x + btnAreaX + 220, wPos.y + 38),
        IM_COL32(64, 64, 102, 255), 6.0f, 0, 1.0f);
    dl->AddText(ImVec2(wPos.x + btnAreaX + 130, wPos.y + 17),
        ColToU32(COL_TEXT_MUTED), ICON_FA_DOWNLOAD);
    dl->AddText(ImVec2(wPos.x + btnAreaX + 148, wPos.y + 17),
        ColToU32(COL_TEXT_MUTED), "Export");
    ImGui::InvisibleButton("##ExportBtn", ImVec2(102, 26));
    if (ImGui::IsItemClicked()) exportOpen_ = !exportOpen_;
    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(btnAreaX + 230, 16));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_CYAN);
    dl->AddText(ImVec2(wPos.x + btnAreaX + 228, wPos.y + 17),
        ColToU32(COL_CYAN), "View All \xe2\x86\x92");
    ImGui::InvisibleButton("##ViewAllBtn", ImVec2(80, 22));
    ImGui::PopStyleColor();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(7);

    if (filterOpen_) {
        ImGui::SetNextWindowPos(ImVec2(wPos.x + btnAreaX - 2, wPos.y + 40));
        ImGui::SetNextWindowSize(ImVec2(200, 160));
        ImGui::PushStyleColor(ImGuiCol_PopupBg, COL_BG_CARD);
        ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
        ImGui::Begin("##FilterPopup", &filterOpen_,
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar);
        ImGui::Text("Filter Options");
        ImGui::Separator();
        ImGui::Combo("Protocol", &filterProtocol_, "All\0TCP\0UDP\0ICMP\0");
        ImGui::Combo("Action", &filterAction_, "All\0ALLOW\0BLOCK\0");
        ImGui::Combo("Direction", &filterDirection_, "All\0Inbound\0Outbound\0");
        ImGui::Separator();
        if (ImGui::Button("Apply", ImVec2(-1, 0))) { filterOpen_ = false; }
        ImGui::End();
        ImGui::PopStyleColor(2);
    }

    if (exportOpen_) {
        ImGui::SetNextWindowPos(ImVec2(wPos.x + btnAreaX + 116, wPos.y + 40));
        ImGui::SetNextWindowSize(ImVec2(160, 80));
        ImGui::PushStyleColor(ImGuiCol_PopupBg, COL_BG_CARD);
        ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
        ImGui::Begin("##ExportPopup", &exportOpen_,
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar);
        ImGui::Text("Export");
        ImGui::Separator();
        if (ImGui::MenuItem("Export as CSV")) {
            if (logger_) {
                auto lines = logger_->readLastLines(50);
                std::ofstream out("dashboard_export.csv");
                if (out.is_open()) {
                    out << "Timestamp,PacketID,SourceIP,DestIP,Port,Protocol,Direction,Action,RuleID,Threat\n";
                    for (const auto& l : lines) out << l << "\n";
                    out.close();
                }
            }
            exportOpen_ = false;
        }
        if (ImGui::MenuItem("Export as TXT")) {
            if (logger_) {
                auto lines = logger_->readLastLines(50);
                std::ofstream out("dashboard_export.txt");
                if (out.is_open()) {
                    for (const auto& l : lines) out << l << "\n";
                    out.close();
                }
            }
            exportOpen_ = false;
        }
        ImGui::End();
        ImGui::PopStyleColor(2);
    }

    float headerY = 48;
    float headerH = 32.0f;
    float tableW = wW;

    float colWidths[] = {70, 160, 90, 90, 110, 90, 120, 130};
    float colOffsets[8];
    float acc = 0;
    for (int c = 0; c < 8; c++) { colOffsets[c] = acc; acc += colWidths[c]; }

    ImVec2 headerMin = ImVec2(wPos.x, wPos.y + headerY);
    ImVec2 headerMax = ImVec2(wPos.x + tableW, wPos.y + headerY + headerH);
    dl->AddRectFilled(headerMin, headerMax, IM_COL32(18, 18, 36, 255));

    const char* headers[] = {"ID", "SOURCE IP", "DEST PORT", "PROTOCOL", "DIRECTION", "ACTION", "MATCHED RULE", "TIMESTAMP"};
    ImVec4 headerCol = ImVec4(0.42f, 0.44f, 0.56f, 1.0f);
    ImGui::SetWindowFontScale(0.78f);
    for (int c = 0; c < 8; c++) {
        dl->AddText(
            ImVec2(wPos.x + colOffsets[c] + 12, wPos.y + headerY + 9),
            ColToU32(headerCol),
            headers[c]);
    }
    ImGui::SetWindowFontScale(1.0f);

    float rowsY = headerY + headerH;
    float rowsH = ImGui::GetWindowHeight() - rowsY;
    if (rowsH < 50) rowsH = 50;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0,0,0,0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::SetCursorPos(ImVec2(0, rowsY));
    ImGui::BeginChild("##LogRows", ImVec2(0, rowsH), false,
        ImGuiWindowFlags_AlwaysVerticalScrollbar);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    std::vector<std::string> logLines;
    if (logger_) {
        logLines = logger_->getSessionLog();
    }

    if (logLines.empty()) {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 40);
        ImVec2 textSz = ImGui::CalcTextSize("No packets logged yet");
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - textSz.x) * 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.4f, 0.55f, 1.0f));
        ImGui::Text("No packets logged yet");
        ImGui::PopStyleColor();
        ImGui::EndChild();
        return;
    }

    struct LogEntry {
        std::string id, srcIP, dstPort, protocol, direction, action, matchedRule, timestamp;
    };
    std::vector<LogEntry> entries;
    for (const auto& line : logLines) {
        std::istringstream ss(line);
        std::vector<std::string> f;
        std::string tok;
        while (std::getline(ss, tok, ',')) f.push_back(tok);
        if (f.size() < 10) continue;

        if (filterProtocol_ != 0) {
            static const char* ps[] = {"", "TCP", "UDP", "ICMP"};
            if (f[5] != ps[filterProtocol_]) continue;
        }
        if (filterAction_ != 0) {
            static const char* as[] = {"", "ALLOW", "BLOCK"};
            if (f[7] != as[filterAction_]) continue;
        }
        if (filterDirection_ != 0) {
            static const char* ds[] = {"", "INBOUND", "OUTBOUND"};
            if (f[6] != ds[filterDirection_]) continue;
        }

        entries.push_back({
            "#" + f[1],
            f[2],
            f[4],
            f[5],
            f[6],
            f[7],
            (f[8].empty() || f[8] == "0") ? "DEFAULT" : "R-" + f[8],
            f[0]
        });
    }

    float rowH = 34.0f;
    ImDrawList* rowDl = ImGui::GetWindowDrawList();

    ImVec2 mousePos = ImGui::GetIO().MousePos;

    for (int i = 0; i < (int)entries.size(); i++) {
        const auto& e = entries[i];

        ImVec2 rowScreenPos = ImGui::GetCursorScreenPos();
        ImVec2 rowMin = rowScreenPos;
        ImVec2 rowMax = ImVec2(rowScreenPos.x + ImGui::GetContentRegionAvail().x, rowScreenPos.y + rowH);

        bool hovered = (mousePos.x >= rowMin.x && mousePos.x <= rowMax.x &&
                        mousePos.y >= rowMin.y && mousePos.y <= rowMax.y);
        if (hovered) {
            rowDl->AddRectFilled(rowMin, rowMax, IM_COL32(30, 30, 55, 255));
        }

        if (i > 0) {
            rowDl->AddLine(
                ImVec2(rowMin.x + 12, rowMin.y),
                ImVec2(rowMax.x - 12, rowMin.y),
                IM_COL32(35, 35, 58, 180));
        }

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[0] + 12, rowMin.y + 9),
            IM_COL32(100, 130, 190, 255), e.id.c_str());

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[1] + 12, rowMin.y + 9),
            IM_COL32(210, 210, 230, 255), e.srcIP.c_str());

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[2] + 12, rowMin.y + 9),
            IM_COL32(210, 210, 230, 255), e.dstPort.c_str());

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[3] + 12, rowMin.y + 9),
            IM_COL32(210, 210, 230, 255), e.protocol.c_str());

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[4] + 12, rowMin.y + 9),
            IM_COL32(210, 210, 230, 255), e.direction.c_str());

        if (e.action == "BLOCK") {
            ImVec2 pillMin = ImVec2(rowMin.x + colOffsets[5] + 12, rowMin.y + 7);
            ImVec2 pillMax = ImVec2(rowMin.x + colOffsets[5] + 72, rowMin.y + 25);
            rowDl->AddRectFilled(pillMin, pillMax, IM_COL32(200, 30, 50, 255), 12.0f);
            ImVec2 txtSz = ImGui::CalcTextSize("BLOCK");
            rowDl->AddText(
                ImVec2(pillMin.x + (72 - txtSz.x) * 0.5f, pillMin.y + (18 - txtSz.y) * 0.5f),
                IM_COL32(255, 255, 255, 255), "BLOCK");
        } else {
            ImVec2 pillMin = ImVec2(rowMin.x + colOffsets[5] + 12, rowMin.y + 7);
            ImVec2 pillMax = ImVec2(rowMin.x + colOffsets[5] + 72, rowMin.y + 25);
            rowDl->AddRectFilled(pillMin, pillMax, IM_COL32(20, 150, 80, 255), 12.0f);
            ImVec2 txtSz = ImGui::CalcTextSize("ALLOW");
            rowDl->AddText(
                ImVec2(pillMin.x + (72 - txtSz.x) * 0.5f, pillMin.y + (18 - txtSz.y) * 0.5f),
                IM_COL32(255, 255, 255, 255), "ALLOW");
        }

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[6] + 12, rowMin.y + 9),
            IM_COL32(160, 165, 190, 255), e.matchedRule.c_str());

        rowDl->AddText(ImVec2(rowMin.x + colOffsets[7] + 12, rowMin.y + 9),
            IM_COL32(140, 145, 170, 255), e.timestamp.c_str());

        ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, rowH));
    }

    ImGui::EndChild();
}
