#include "TrafficPanel.h"
#include "implot.h"
#include "../../include/ImGuiColors.h"
#include "../../include/FirewallStats.h"
#include <cmath>
#include <string>
#include <sstream>

static ImU32 C(ImVec4 col) {
    return IM_COL32((int)(col.x*255), (int)(col.y*255), (int)(col.z*255), (int)(col.w*255));
}

void TrafficPanel::UpdateData(FirewallStats* stats) {
    if (!stats) return;
    allowedBuf_[bufferOffset_] = (float)(stats->totalAllowed - lastAllowed_);
    blockedBuf_[bufferOffset_] = (float)(stats->totalBlocked - lastBlocked_);
    lastAllowed_ = stats->totalAllowed;
    lastBlocked_ = stats->totalBlocked;
    bufferOffset_ = (bufferOffset_ + 1) % 60;
}

void TrafficPanel::Render() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wPos = ImGui::GetWindowPos();
    float startY = ImGui::GetCursorPosY();
    float contentW = ImGui::GetContentRegionAvail().x;

    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 4),
        C(COL_TEXT), "Traffic Monitor");
    dl->AddText(ImVec2(wPos.x + 24, wPos.y + startY + 28),
        C(COL_TEXT_MUTED), "Real-time network packet analysis");

    float btnY = startY + 56;
    int timeRanges[] = {0, 1, 5, 10};
    const char* timeLabels[] = {"Live", "1 Min", "5 Min", "10 Min"};
    ImGui::SetCursorPos(ImVec2(24, btnY));
    for (int i = 0; i < 4; ++i) {
        bool active = (timeFilter_ == i);
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0.831f, 1.0f, 0.15f));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_CYAN);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        }
        if (ImGui::Button(timeLabels[i], ImVec2(80, 32))) {
            timeFilter_ = i;
        }
        ImGui::PopStyleColor(2);
        if (i < 3) ImGui::SameLine(0, 4);
    }

    float chart1Y = btnY + 48;
    ImGui::SetCursorPos(ImVec2(24, chart1Y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::BeginChild("##Chart1", ImVec2(contentW - 24, 240), true);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);

    dl->AddText(ImVec2(wPos.x + 40, wPos.y + chart1Y + 14),
        C(COL_TEXT), "Allowed vs Blocked");
    dl->AddText(ImVec2(wPos.x + 40, wPos.y + chart1Y + 32),
        C(COL_TEXT_MUTED), "Last 60 seconds \xe2\x80\x94 real-time");

    float legendX = contentW - 220;
    dl->AddCircleFilled(ImVec2(wPos.x + legendX, wPos.y + chart1Y + 20), 4.0f, IM_COL32(0, 212, 255, 255));
    dl->AddText(ImVec2(wPos.x + legendX + 10, wPos.y + chart1Y + 14), IM_COL32(224, 224, 255, 255), "Allowed");
    dl->AddCircleFilled(ImVec2(wPos.x + legendX + 80, wPos.y + chart1Y + 20), 4.0f, IM_COL32(255, 51, 102, 255));
    dl->AddText(ImVec2(wPos.x + legendX + 90, wPos.y + chart1Y + 14), IM_COL32(224, 224, 255, 255), "Blocked");
    dl->AddText(ImVec2(wPos.x + legendX + 160, wPos.y + chart1Y + 14), IM_COL32(107, 122, 154, 255), "NOW");

    ImGui::SetCursorPos(ImVec2(8, 56));
    ImPlot::PushStyleColor(ImPlotCol_PlotBg, ImVec4(0.067f, 0.094f, 0.153f, 1.0f));
    ImPlot::PushStyleColor(ImPlotCol_AxisGrid, ImVec4(0.118f, 0.165f, 0.227f, 1.0f));
    ImPlot::PushStyleColor(ImPlotCol_AxisText, ImVec4(0.42f, 0.48f, 0.6f, 1.0f));

    if (ImPlot::BeginPlot("##TrafficTrends", ImVec2(-1, -1),
        ImPlotFlags_NoTitle | ImPlotFlags_NoMouseText | ImPlotFlags_NoLegend))
    {
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
        ImPlot::PlotShaded("Allowed", allowedBuf_, 60, 0.0, 1.0, 0.0, allowedSpec);

        ImPlotSpec blockedSpec;
        blockedSpec.LineColor = ImVec4(1.0f, 0.2f, 0.4f, 1.0f);
        blockedSpec.LineWeight = 2.0f;
        ImPlot::PlotLine("Blocked", blockedBuf_, 60, 1.0, 0.0, blockedSpec);

        ImPlot::EndPlot();
    }
    ImPlot::PopStyleColor(3);
    ImGui::EndChild();

    float chart2Y = chart1Y + 256;
    ImGui::SetCursorPos(ImVec2(24, chart2Y));
    float halfW = (contentW - 24 - 16) * 0.5f;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::BeginChild("##ProtocolBreakdown", ImVec2(halfW, 200), true);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);

    dl->AddText(ImVec2(wPos.x + 40, wPos.y + chart2Y + 14),
        C(COL_TEXT), "Protocol Breakdown");

    int totalProto = stats_->tcpPackets + stats_->udpPackets + stats_->icmpPackets;

    if (totalProto == 0) {
        dl->AddText(ImVec2(wPos.x + 40, wPos.y + chart2Y + 80),
            C(COL_TEXT_MUTED), "No traffic data available yet.");
    } else {
    float barX = wPos.x + 40;
    float barY = wPos.y + chart2Y + 50;
    float barW = halfW - 32;
    float barH = 28.0f;
    float gap = 12.0f;

    struct ProtoBar { const char* name; int count; int pct; ImU32 color; };
    ProtoBar bars[] = {
        {"TCP", stats_->tcpPackets, stats_->tcpPackets * 100 / totalProto, C(ImVec4(0, 0.831f, 1.0f, 1))},
        {"UDP", stats_->udpPackets, stats_->udpPackets * 100 / totalProto, C(COL_AMBER)},
        {"ICMP", stats_->icmpPackets, stats_->icmpPackets * 100 / totalProto, C(COL_GREEN)}
    };

    for (int i = 0; i < 3; ++i) {
        dl->AddRectFilled(
            ImVec2(barX, barY + (barH + gap) * i),
            ImVec2(barX + barW, barY + (barH + gap) * i + barH),
            C(COL_BG_INPUT), 4.0f);
        float pctW = barW * bars[i].pct / 100.0f;
        dl->AddRectFilled(
            ImVec2(barX, barY + (barH + gap) * i),
            ImVec2(barX + pctW, barY + (barH + gap) * i + barH),
            bars[i].color, 4.0f);
        std::string label = bars[i].name + std::string(" ") + std::to_string(bars[i].pct) + "%";
        dl->AddText(ImVec2(barX + 8, barY + (barH + gap) * i + 6),
            C(COL_TEXT), label.c_str());
    }
    }

    ImGui::EndChild();

    ImGui::SameLine(0, 16);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::BeginChild("##DirectionBreakdown", ImVec2(0, 200), true);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);

    dl->AddText(ImVec2(wPos.x + halfW + 56, wPos.y + chart2Y + 14),
        C(COL_TEXT), "Traffic Direction");

    if (ImPlot::BeginPlot("##PieChart", ImVec2(-1, -1),
        ImPlotFlags_Equal | ImPlotFlags_NoMouseText | ImPlotFlags_NoTitle | ImPlotFlags_NoLegend))
    {
        const char* labels[] = {"Inbound", "Outbound"};
        double data[] = {(double)stats_->inboundPackets, (double)stats_->outboundPackets};
        ImU32 fillColors[] = {C(COL_CYAN), C(COL_PURPLE)};
        ImPlotSpec spec;
        spec.FillColors = fillColors;
        spec.FillAlpha = 1.0f;
        ImPlot::PlotPieChart(labels, data, 2, 0.5, 0.5, 0.4, "%.0f%%", 90, spec);
        ImPlot::EndPlot();
    }

    ImGui::EndChild();

    float tableY = chart2Y + 256;
    ImGui::SetCursorPos(ImVec2(24, tableY));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_CARD);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Border, COL_BORDER_CARD);
    ImGui::BeginChild("##PacketTable", ImVec2(contentW - 24, 300), true);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);

    dl->AddText(ImVec2(wPos.x + 40, wPos.y + tableY + 14),
        C(COL_TEXT), "Recent Packet Activity");
    dl->AddText(ImVec2(wPos.x + 40, wPos.y + tableY + 32),
        C(COL_TEXT_MUTED), "Live packet log — showing allowed and blocked traffic");

    float hdrY = tableY + 52;
    float colX[] = {40, 160, 260, 340, 420};
    const char* colLabels[] = {"SOURCE IP", "ACTION", "PROTOCOL", "PORT", "TIMESTAMP"};
    ImGui::SetWindowFontScale(0.75f);
    for (int c = 0; c < 5; ++c) {
        dl->AddText(ImVec2(wPos.x + colX[c], wPos.y + hdrY),
            C(COL_TEXT_MUTED), colLabels[c]);
    }
    ImGui::SetWindowFontScale(1.0f);

    float lineY = hdrY + 24;
    dl->AddLine(ImVec2(wPos.x + 36, wPos.y + lineY),
        ImVec2(wPos.x + contentW - 12, wPos.y + lineY),
        IM_COL32(40, 40, 65, 255));

    ImGui::SetCursorPos(ImVec2(12, hdrY - tableY + 28));
    ImGui::BeginChild("##PacketRows", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);

    std::vector<std::string> logLines;
    if (logger_) logLines = logger_->getSessionLog();

    if (logLines.empty()) {
        ImGui::SetCursorPosY(40);
        ImVec2 txtSz = ImGui::CalcTextSize("No packets logged yet");
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - txtSz.x) * 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        ImGui::Text("No packets logged yet");
        ImGui::PopStyleColor();
    } else {
        float rowH = 24.0f;
        float cX[] = {8, 128, 198, 268, 338};
        int start = (int)logLines.size() - 100;
        if (start < 0) start = 0;
        for (int i = start; i < (int)logLines.size(); ++i) {
            std::istringstream ss(logLines[i]);
            std::vector<std::string> f;
            std::string tok;
            while (std::getline(ss, tok, ',')) f.push_back(tok);
            if (f.size() < 8) continue;

            ImVec2 rMin = ImGui::GetCursorScreenPos();
            float rowY = ImGui::GetCursorPosY();
            ImVec2 rMax = ImVec2(rMin.x + ImGui::GetContentRegionAvail().x, rMin.y + rowH);

            if (ImGui::IsMouseHoveringRect(rMin, rMax)) {
                ImGui::GetWindowDrawList()->AddRectFilled(rMin, rMax, IM_COL32(28, 28, 50, 255));
            }

            ImGui::SetWindowFontScale(0.78f);
            ImGui::SetCursorPosX(cX[0]);
            ImGui::TextColored(COL_CYAN, "%s", f[2].c_str());
            ImGui::SameLine(cX[1]);
            ImGui::TextColored(f[7] == "BLOCK" ? COL_RED : ImVec4(0.235f, 0.784f, 0.471f, 1.0f), "%s", f[7].c_str());
            ImGui::SameLine(cX[2]);
            ImGui::Text("%s", f[5].c_str());
            ImGui::SameLine(cX[3]);
            ImGui::Text("%s", f[4].c_str());
            ImGui::SameLine(cX[4]);
            ImGui::TextColored(COL_TEXT_MUTED, "%s", f[0].c_str());
            ImGui::SetWindowFontScale(1.0f);

            ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, rowH - ImGui::GetTextLineHeightWithSpacing()));
        }
    }

    ImGui::EndChild();

    ImGui::EndChild();
}
