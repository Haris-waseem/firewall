#include "FirewallGUI.h"
#include <GLFW/glfw3.h>
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "panels/DashboardPanel.h"
#include "panels/RulesPanel.h"
#include "panels/BlacklistPanel.h"
#include "panels/TrafficPanel.h"
#include "panels/ThreatsPanel.h"
#include "panels/LogsPanel.h"
#include "panels/SettingsPanel.h"
#include "imgui_internal.h"

#include "../include/IconsFontAwesome.h"

#include <iostream>
#include <cmath>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

#ifdef _WIN32
#include <windows.h>
static std::string getExeDir() {
    char buf[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string path(buf);
    auto pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(0, pos + 1) : "";
}
#else
#include <unistd.h>
static std::string getExeDir() {
    char buf[4096] = {0};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return "";
    buf[len] = '\0';
    std::string path(buf);
    auto pos = path.find_last_of('/');
    return (pos != std::string::npos) ? path.substr(0, pos + 1) : "";
}
#endif

static void glfw_error_callback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

FirewallGUI::FirewallGUI(RuleEngine* e, PacketProcessor* p, TrafficMonitor* m, FileLogger* fl, MongoLogger* ml,
                         FirewallStats* s, Stack* st, Queue* q, PacketSimulator* sim)
    : engine_(e), processor_(p), monitor_(m), fileLogger_(fl), mongoLogger_(ml),
      stats_(s), history_(st), queue_(q), simulator_(sim),
      dashboardPanel_(nullptr), rulesPanel_(nullptr), blacklistPanel_(nullptr),
      trafficPanel_(nullptr), threatsPanel_(nullptr), logsPanel_(nullptr),
      settingsPanel_(nullptr), terminalPanel_(nullptr),
      notifications_(), notificationOpen_(false), notificationCount_(0),
      uiFontScale_(1.0f), uiFont_(nullptr), monoFont_(nullptr), window_(nullptr),
      appStartTime_(std::time(nullptr)) {

    dashboardPanel_ = new DashboardPanel(s, e, p, m, st, fl);
    rulesPanel_ = new RulesPanel(e);
    blacklistPanel_ = new BlacklistPanel(e);
    trafficPanel_ = new TrafficPanel(s, m, fl);
    threatsPanel_ = new ThreatsPanel(s, e);
    logsPanel_ = new LogsPanel(fl, m);
    settingsPanel_ = new SettingsPanel(e, p, m, fl, ml, s, st);
    terminalPanel_ = new TerminalPanel(e, p, fl, m, s, st, sim);
    terminalPanel_->SetOpenPtr(&terminalOpen_);
    terminalPanel_->SetMaximizedPtr(&terminalMaximized_);
}

FirewallGUI::~FirewallGUI() {
    delete dashboardPanel_;
    delete rulesPanel_;
    delete blacklistPanel_;
    delete trafficPanel_;
    delete threatsPanel_;
    delete logsPanel_;
    delete settingsPanel_;
    delete terminalPanel_;
}

bool FirewallGUI::Init() {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return false;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    window_ = glfwCreateWindow(1440, 900, "Terminal - Firewall Dashboard v1.0", NULL, NULL);
    if (window_ == NULL) return false;

    glfwSetWindowSizeLimits(window_, 1024, 768, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();

    ImGuiIO& io = ImGui::GetIO(); (void)io;

    std::string exeDir = getExeDir();
    std::string uiPath = exeDir + "fonts/Inter_18pt-Regular.ttf";
    std::string iconPath = exeDir + "fonts/fa-solid-900.ttf";
    std::string monoPath = exeDir + "fonts/JetBrainsMono-Regular.ttf";

    uiFont_ = io.Fonts->AddFontFromFileTTF(uiPath.c_str(), 16.0f);
    if (!uiFont_) { uiFont_ = io.Fonts->AddFontDefault(); }

    static const ImWchar iconRanges[] = { 0xF000, 0xF2FF, 0 };
    ImFontConfig iconConfig;
    iconConfig.MergeMode = true;
    iconConfig.PixelSnapH = true;
    iconConfig.GlyphOffset.y = 1.0f;
    io.Fonts->AddFontFromFileTTF(iconPath.c_str(), 16.0f, &iconConfig, iconRanges);

    monoFont_ = io.Fonts->AddFontFromFileTTF(monoPath.c_str(), 14.0f);

    if (io.Fonts->Fonts.Size == 0) {
        io.Fonts->AddFontDefault();
    }

    ApplyTheme();

    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    return true;
}

void FirewallGUI::ApplyTheme() {
    ImGuiStyle& style = ImGui::GetStyle();

    style.Colors[ImGuiCol_WindowBg] = COL_BG_PAGE;
    style.Colors[ImGuiCol_ChildBg] = COL_BG_CARD;
    style.Colors[ImGuiCol_PopupBg] = COL_BG_CARD;
    style.Colors[ImGuiCol_Border] = COL_BORDER;
    style.Colors[ImGuiCol_FrameBg] = COL_BG_INPUT;
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.102f, 0.102f, 0.18f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.0f, 0.831f, 1.0f, 0.10f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.0f, 0.831f, 1.0f, 0.20f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.0f, 0.831f, 1.0f, 0.30f);
    style.Colors[ImGuiCol_Header] = ImVec4(0.0f, 0.831f, 1.0f, 0.10f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.0f, 0.831f, 1.0f, 0.15f);
    style.Colors[ImGuiCol_TitleBg] = COL_BG_SIDEBAR;
    style.Colors[ImGuiCol_TitleBgActive] = COL_BG_SIDEBAR;
    style.Colors[ImGuiCol_Tab] = COL_BG_SIDEBAR;
    style.Colors[ImGuiCol_TabHovered] = ImVec4(0.0f, 0.831f, 1.0f, 0.15f);
    style.Colors[ImGuiCol_TabActive] = ImVec4(0.0f, 0.831f, 1.0f, 0.20f);
    style.Colors[ImGuiCol_Text] = COL_TEXT;
    style.Colors[ImGuiCol_TextDisabled] = COL_TEXT_DIM;
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.059f, 0.059f, 0.118f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.165f, 0.165f, 0.29f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.2f, 0.2f, 0.35f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.25f, 0.25f, 0.4f, 1.0f);
    style.Colors[ImGuiCol_Separator] = COL_BORDER;

    style.FrameRounding = 6.0f;
    style.WindowRounding = 8.0f;
    style.PopupRounding = 8.0f;
    style.TabRounding = 6.0f;
    style.ScrollbarSize = 4.0f;
    style.GrabMinSize = 4.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.TabBorderSize = 0.0f;
}

void FirewallGUI::Shutdown() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();

    glfwDestroyWindow(window_);
    glfwTerminate();
}

void FirewallGUI::Run() {
    while (!glfwWindowShouldClose(window_)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        double currentTime = ImGui::GetTime();
        if (currentTime - lastUpdateTime_ >= 1.0) {
            dashboardPanel_->UpdateData();
            trafficPanel_->UpdateData(stats_);
            threatsPanel_->SyncThreats(stats_);
            threatNotificationCount_ = stats_->threatsDetected;
            lastUpdateTime_ = currentTime;
        }

        Render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window_, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.05f, 0.10f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window_);
    }
}

void FirewallGUI::Render() {
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGui::Begin("MainLayout", nullptr, window_flags);

    float totalW = viewport->WorkSize.x;
    float totalH = viewport->WorkSize.y;

    ImGui::Dummy(ImVec2(totalW, totalH));
    ImGui::SetCursorPos(ImVec2(0, 0));

    RenderLeftSidebar();

    float rightW = rightSidebarOpen_ ? kRightSidebarW : 0.0f;
    float middleW = totalW - kLeftSidebarW - rightW;

    float contentH = totalH - kTopBarH;

    float desiredHeight = 0.0f;
    if (terminalOpen_) {
        if (terminalMaximized_) {
            desiredHeight = contentH - kTopBarH - 36.0f;
        } else if (terminalPanel_->minimized_) {
            desiredHeight = 36.0f;
        } else {
            desiredHeight = 280.0f;
        }
    }
    if (desiredHeight != terminalAnimTargetHeight_) {
        terminalAnimStartHeight_ = terminalAnimHeight_;
        terminalAnimTargetHeight_ = desiredHeight;
        terminalAnimStartTime_ = ImGui::GetTime();
    }
    const float animDuration = 0.2f;
    float elapsed = static_cast<float>(ImGui::GetTime() - terminalAnimStartTime_);
    float t = ImClamp(elapsed / animDuration, 0.0f, 1.0f);
    terminalAnimHeight_ = ImLerp(terminalAnimStartHeight_, terminalAnimTargetHeight_, t);

    float contentAreaH = contentH - terminalAnimHeight_;

    ImGui::SetCursorPos(ImVec2(kLeftSidebarW, 0));
    ImGui::BeginChild("TopBar", ImVec2(middleW, kTopBarH), false);
    RenderTopBar();
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(kLeftSidebarW, kTopBarH));
    ImGui::BeginChild("ContentArea", ImVec2(middleW, contentAreaH), false);

    switch (activePage_) {
        case 0: dashboardPanel_->Render();
                if (dashboardPanel_->pendingNavigation_ >= 0) {
                    activePage_ = dashboardPanel_->pendingNavigation_;
                    dashboardPanel_->pendingNavigation_ = -1;
                }
                break;
        case 1: rulesPanel_->Render(); break;
        case 2: blacklistPanel_->Render(); break;
        case 3: trafficPanel_->Render(); break;
        case 4: threatsPanel_->Render(); break;
        case 5: logsPanel_->Render(); break;
        case 6: settingsPanel_->Render(); break;
    }

    ImGui::EndChild();

    if (terminalAnimHeight_ > 20.0f) {
        float termX = viewport->WorkPos.x + kLeftSidebarW;
        float termY = viewport->WorkPos.y + totalH - terminalAnimHeight_;
        terminalPanel_->Render(termX, termY, middleW, terminalAnimHeight_);
    }

    if (rightSidebarOpen_) {
        ImGui::SetCursorPos(ImVec2(kLeftSidebarW + middleW, 0));
        ImGui::BeginChild("RightSidebar", ImVec2(rightW, totalH), false);
        ImGui::Dummy(ImVec2(rightW, totalH));
        ImGui::SetCursorPos(ImVec2(0, 0));
        RenderRightSidebar();
        ImGui::EndChild();
    }

    RenderNotifications();

    ImGui::End();
}

void FirewallGUI::RenderLeftSidebar() {
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_BG_SIDEBAR);
    ImGui::BeginChild("LeftSidebar", ImVec2(kLeftSidebarW, ImGui::GetWindowHeight()), false);
    ImGui::Dummy(ImVec2(kLeftSidebarW, ImGui::GetWindowHeight()));
    ImGui::SetCursorPos(ImVec2(0, 0));

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 winPos = ImGui::GetWindowPos();

    dl->AddRectFilled(winPos, ImVec2(winPos.x + kLeftSidebarW, winPos.y + ImGui::GetWindowHeight()), IM_COL32(17, 17, 40, 255));

    ImGui::SetCursorPos(ImVec2(16, 16));
    dl->AddRectFilled(ImVec2(winPos.x + 16, winPos.y + 16), ImVec2(winPos.x + 56, winPos.y + 56), IM_COL32(0, 212, 255, 255), 10.0f);
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
    ImGui::SetCursorPos(ImVec2(24, 24));
    ImGui::Text(ICON_FA_SHIELD);
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(16, 68));
    dl->AddRectFilled(
        ImVec2(winPos.x + 16, winPos.y + 68),
        ImVec2(winPos.x + 56, winPos.y + 69),
        IM_COL32(30, 30, 58, 255)
    );

    const char* icons[] = {
        ICON_FA_TH_LARGE,
        ICON_FA_SHIELD,
        ICON_FA_BAN,
        ICON_FA_HEART_BEAT,
        ICON_FA_EXCLAMATION_TRIANGLE,
        ICON_FA_FILE_TEXT_O,
        ICON_FA_COG
    };
    ImU32 activeCol = IM_COL32(0, 212, 255, 255);

    ImGui::SetCursorPos(ImVec2(12, 80));
    ImGui::PushFont(uiFont_);
    for (int i = 0; i < 7; ++i) {
        ImGui::SetCursorPosX(12);
        ImGui::PushID(i);

        ImVec2 itemMin = ImVec2(winPos.x + 12, winPos.y + ImGui::GetCursorPosY());
        if (i == activePage_) {
            float pulse = 0.5f + 0.5f * sinf((float)ImGui::GetTime() * 2.5f);
            ImU32 pulseBg = IM_COL32(0, 212, 255, (int)(15 + 20 * pulse));
            ImU32 pulseBorder = IM_COL32(0, 212, 255, (int)(40 + 36 * pulse));
            dl->AddRectFilled(itemMin, ImVec2(itemMin.x + 48, itemMin.y + 48), pulseBg, 12.0f);
            dl->AddRect(itemMin, ImVec2(itemMin.x + 48, itemMin.y + 48), pulseBorder, 12.0f, 0, 1.5f);
        }

        bool isActive = (i == activePage_);
        ImVec4 iconCol = isActive ? ImVec4(0, 0.831f, 1.0f, 1) : ImVec4(0.533f, 0.533f, 0.667f, 1);

        ImVec2 btnMin = ImVec2(winPos.x + 12, winPos.y + ImGui::GetCursorPosY());
        ImVec2 btnMax = ImVec2(btnMin.x + 48, btnMin.y + 48);
        bool isHovered = ImGui::IsMouseHoveringRect(btnMin, btnMax);
        if (!isActive && isHovered) {
            dl->AddRectFilled(btnMin, btnMax, IM_COL32(255, 255, 255, 8), 12.0f);
        }

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, iconCol);
        if (ImGui::Button(icons[i], ImVec2(48, 48))) {
            activePage_ = i;
        }
        ImGui::PopStyleColor(2);
        ImGui::PopID();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);

        if (i == 4 && threatNotificationCount_ > 0) {
            float dotR = 4.0f + 1.0f * sinf((float)ImGui::GetTime() * 3.0f);
            dl->AddCircleFilled(
                ImVec2(itemMin.x + 44, itemMin.y + 4),
                dotR, IM_COL32(255, 23, 68, 255));
        }
    }
    ImGui::PopFont();

    float leftWinH = ImGui::GetWindowHeight();
    float leftCurY = ImGui::GetCursorPosY();
    if (leftCurY < leftWinH - 68.0f) {
        ImGui::Dummy(ImVec2(0, leftWinH - 68.0f - leftCurY));
    }

    ImGui::SetCursorPos(ImVec2(12, ImGui::GetCursorPosY()));
    ImVec2 termMin = ImVec2(winPos.x + 12, winPos.y + ImGui::GetCursorPosY());
    dl->AddRectFilled(termMin, ImVec2(termMin.x + 48, termMin.y + 48),
        terminalOpen_ ? IM_COL32(0, 255, 153, 46) : IM_COL32(0, 255, 153, 25), 10.0f);
    dl->AddRect(termMin, ImVec2(termMin.x + 48, termMin.y + 48),
        IM_COL32(0, 255, 153, 64), 10.0f);

    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.6f, 1.0f));
    if (ImGui::Button(ICON_FA_CODE, ImVec2(48, 48))) {
        terminalOpen_ = !terminalOpen_;
        if (terminalOpen_) terminalMaximized_ = false;
    }
    ImGui::PopStyleColor(2);
    ImGui::PopFont();

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void FirewallGUI::RenderTopBar() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 winPos = ImGui::GetWindowPos();

    const char* titles[] = {"Dashboard", "Firewall Rules", "Blacklist & Whitelist", "Traffic Monitor", "Threat Alerts", "System Logs", "Settings"};
    const char* breadcrumbs[] = {"Terminal / Dashboard", "Terminal / Rules", "Terminal / Blacklist", "Terminal / Traffic", "Terminal / Threats", "Terminal / Logs", "Terminal / Settings"};

    ImGui::SetCursorPos(ImVec2(24, 8));
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::Text("%s", titles[activePage_]);
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(24, 30));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_DIM);
    ImGui::SetWindowFontScale(0.85f);
    ImGui::Text("%s", breadcrumbs[activePage_]);
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();

    float searchW = 340.0f;
    float searchX = ImGui::GetWindowWidth() * 0.5f - searchW * 0.5f;
    ImGui::SetCursorPos(ImVec2(searchX, 10));
    ImGui::PushItemWidth(searchW);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.07f, 0.07f, 0.14f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.20f, 0.20f, 0.35f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushFont(uiFont_);
    ImGui::InputTextWithHint("##search", ICON_FA_SEARCH "  Search IPs, rules, ports...", searchBuffer_, 256);
    ImGui::PopFont();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::PopItemWidth();

    float rightX = ImGui::GetWindowWidth() - 280.0f;

    ImGui::SetCursorPos(ImVec2(rightX, 12));
    ImVec2 pillMin = ImVec2(winPos.x + rightX - 4, winPos.y + 10);
    ImVec2 pillMax = ImVec2(winPos.x + rightX + 130, winPos.y + 38);
    dl->AddRectFilled(pillMin, pillMax, IM_COL32(20, 60, 40, 255), 16.0f);
    dl->AddRect(pillMin, pillMax, IM_COL32(40, 120, 80, 255), 16.0f, 0, 1.0f);

    float dotPulse = 0.7f + 0.3f * sinf((float)ImGui::GetTime() * 3.0f);
    dl->AddCircleFilled(
        ImVec2(winPos.x + rightX + 8, winPos.y + 24),
        4.0f, IM_COL32(0, 230, 118, (int)(dotPulse * 255)));

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.902f, 0.463f, 1.0f));
    ImGui::SetWindowFontScale(0.85f);
    ImGui::SetCursorPos(ImVec2(rightX + 16, 14));
    ImGui::Text("System Online");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();

    float bellX = rightX + 140;
    ImGui::SetCursorPos(ImVec2(bellX, 10));
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
    std::string bellLabel = std::string(ICON_FA_BELL);
    if (ImGui::Button(bellLabel.c_str(), ImVec2(32, 28))) {
        notificationOpen_ = !notificationOpen_;
    }
    ImGui::PopStyleColor();
    ImGui::PopFont();

    {
        int badgeCount = notificationCount_ > 0 ? notificationCount_ : 3;
        std::string countStr = std::to_string(badgeCount);
        ImVec2 badgeCenter = ImVec2(winPos.x + bellX + 26, winPos.y + 12);
        dl->AddCircleFilled(badgeCenter, 8.0f, IM_COL32(255, 23, 68, 255));
        ImVec2 txtSize = ImGui::CalcTextSize(countStr.c_str());
        dl->AddText(
            ImVec2(badgeCenter.x - txtSize.x * 0.5f, badgeCenter.y - txtSize.y * 0.5f),
            IM_COL32(255, 255, 255, 255), countStr.c_str());
    }

    float avX = rightX + 185;
    ImGui::SetCursorPos(ImVec2(avX, 10));
    ImVec2 avCenter = ImVec2(winPos.x + avX + 16, winPos.y + 24);
    dl->AddCircleFilled(avCenter, 16.0f, IM_COL32(124, 77, 255, 255));
    dl->AddCircle(avCenter, 17.0f, IM_COL32(42, 42, 74, 255), 0, 2.0f);
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
    ImVec2 adSize = ImGui::CalcTextSize("AD");
    ImGui::SetCursorPos(ImVec2(avX + 16 - adSize.x * 0.5f, 24 - adSize.y * 0.5f));
    ImGui::Text("AD");
    ImGui::PopStyleColor();
    ImGui::PopFont();
}

void FirewallGUI::RenderRightSidebar() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 winPos = ImGui::GetWindowPos();
    float winW = ImGui::GetWindowWidth();
    float winH = ImGui::GetWindowHeight();

    dl->AddRectFilled(winPos, ImVec2(winPos.x + winW, winPos.y + winH), IM_COL32(17, 17, 40, 255));
    dl->AddLine(ImVec2(winPos.x, winPos.y), ImVec2(winPos.x, winPos.y + winH), IM_COL32(30, 30, 58, 255), 1.0f);

    // ─── Quick Stats ───
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::SetCursorPos(ImVec2(16, 16));
    ImGui::Text(ICON_FA_SIGNAL "  Quick Stats");
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(16, 48));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(22, 22, 42, 255));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::BeginChild("##StatsBox", ImVec2(winW - 32, 160), true);
    ImGui::PopStyleVar();

    struct QuickStat { const char* icon; const char* label; std::string value; ImVec4 color; };
    QuickStat qstats[] = {
        { ICON_FA_CHECK_CIRCLE,  "Allowed",  "0", COL_GREEN },
        { ICON_FA_BAN,           "Blocked",  "0", COL_RED },
        { ICON_FA_EXCLAMATION_TRIANGLE, "Threats", "0", COL_AMBER },
        { ICON_FA_WIFI,          "Active Connections", "0", COL_CYAN },
    };

    if (stats_) {
        qstats[0].value = std::to_string(stats_->totalAllowed);
        qstats[1].value = std::to_string(stats_->totalBlocked);
        qstats[2].value = std::to_string(stats_->threatsDetected);
        qstats[3].value = std::to_string(stats_->activeConnections);
    }

    ImGui::PushFont(uiFont_);
    for (int i = 0; i < 4; ++i) {
        float y = (float)i * 36.0f;
        ImGui::SetCursorPos(ImVec2(12, y + 6));
        ImGui::PushStyleColor(ImGuiCol_Text, qstats[i].color);
        ImGui::Text("%s", qstats[i].icon);
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 8);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        ImGui::SetWindowFontScale(0.85f);
        ImGui::Text("%s", qstats[i].label);
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 4);
        float valX = ImGui::GetWindowWidth() - ImGui::CalcTextSize(qstats[i].value.c_str()).x - 12;
        ImGui::SetCursorPosX(valX);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
        ImGui::Text("%s", qstats[i].value.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PopFont();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    // ─── Recent Activity ───
    ImGui::SetCursorPos(ImVec2(16, 224));
    ImGui::PushFont(uiFont_);
    ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
    ImGui::Text(ICON_FA_CLOCK_O "  Recent Activity");
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(16, 256));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(22, 22, 42, 255));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::BeginChild("##ActivityBox", ImVec2(winW - 32, 240), true);
    ImGui::PopStyleVar();

    ImGui::PushFont(uiFont_);
    if (!stats_ || stats_->activityFeed.empty()) {
        ImGui::SetCursorPos(ImVec2(12, 80));
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        ImGui::SetWindowFontScale(0.85f);
        ImGui::TextWrapped("No activity yet. Packets will appear here as they are processed.");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopStyleColor();
    } else {
        int maxShow = (int)stats_->activityFeed.size();
        if (maxShow > 5) maxShow = 5;
        for (int i = 0; i < maxShow; ++i) {
            const auto& a = stats_->activityFeed[i];
            float y = (float)i * 44.0f;
            ImVec4 actColor;
            switch (a.type) {
                case 1:  actColor = COL_GREEN;  break;
                case 2:  actColor = COL_RED;    break;
                case 3:  actColor = COL_AMBER;  break;
                default: actColor = COL_CYAN;   break;
            }
            ImGui::SetCursorPos(ImVec2(12, y + 4));
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 212, 255, 200));
            ImGui::SetWindowFontScale(0.75f);
            ImGui::Text("%s  %s", a.icon.c_str(), a.sourceIP.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();

            ImGui::SetCursorPos(ImVec2(30, y + 20));
            ImGui::PushStyleColor(ImGuiCol_Text, actColor);
            ImGui::SetWindowFontScale(0.78f);
            ImGui::TextWrapped("%s", a.description.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopFont();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    // ─── System Info ───
    double now = ImGui::GetTime();
    if (now - lastSysInfoTime_ >= 5.0) {
        lastSysInfoTime_ = now;

#ifdef _WIN32
        // CPU usage via GetProcessTimes
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER k, u;
            k.LowPart = kernelTime.dwLowDateTime;
            k.HighPart = kernelTime.dwHighDateTime;
            u.LowPart = userTime.dwLowDateTime;
            u.HighPart = userTime.dwHighDateTime;
            double totalCpuSec = (double)(k.QuadPart + u.QuadPart) / 10000000.0;
            double wallSec = difftime(std::time(nullptr), appStartTime_);
            if (wallSec > 0) {
                int numProcs = 1;
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                numProcs = sysInfo.dwNumberOfProcessors;
                cpuUsage_ = (float)((totalCpuSec / wallSec) * 100.0 / numProcs);
                if (cpuUsage_ > 100.0f) cpuUsage_ = 100.0f;
                if (cpuUsage_ < 0.0f) cpuUsage_ = 0.0f;
            }
        }

        // Memory usage
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            memUsageMB_ = (float)pmc.WorkingSetSize / (1024.0f * 1024.0f);
        }
#endif
    }

    float remaining = ImGui::GetContentRegionAvail().y;
    if (remaining > 200) {
        ImGui::SetCursorPos(ImVec2(16, ImGui::GetCursorPosY() + 16));
        ImGui::PushFont(uiFont_);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
        ImGui::Text(ICON_FA_COG "  System Info");
        ImGui::PopStyleColor();
        ImGui::PopFont();

        ImGui::SetCursorPos(ImVec2(16, ImGui::GetCursorPosY() + 8));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(22, 22, 42, 255));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::BeginChild("##SystemInfo", ImVec2(winW - 32, 80), true);
        ImGui::PopStyleVar();

        // Calculate real uptime
        long elapsedSec = (long)difftime(std::time(nullptr), appStartTime_);
        int hours = elapsedSec / 3600;
        int mins = (elapsedSec % 3600) / 60;
        std::string uptimeStr = std::to_string(hours) + "h " + std::to_string(mins) + "m";

        std::string cpuStr = "CPU: " + std::to_string((int)cpuUsage_) + "." + std::to_string((int)(cpuUsage_ * 10) % 10) + "%";
        std::string memStr = "Mem: " + std::to_string((int)memUsageMB_) + "MB";

        ImGui::PushFont(monoFont_);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        ImGui::SetCursorPos(ImVec2(12, 8));
        ImGui::Text("Uptime: %s", uptimeStr.c_str());
        ImGui::SetCursorPos(ImVec2(12, 28));
        ImGui::Text("%s", cpuStr.c_str());
        ImGui::SetCursorPos(ImVec2(12, 48));
        ImGui::Text("%s", memStr.c_str());
        ImGui::PopStyleColor();
        ImGui::PopFont();

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

void FirewallGUI::AddNotification(const std::string& title, const std::string& msg, ImVec4 color) {
    notifications_.push_back({title, msg, color, ImGui::GetTime()});
    notificationCount_++;
}

void FirewallGUI::RenderNotifications() {
    if (!notificationOpen_) return;

    ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowWidth() - 340, 56));
    ImGui::SetNextWindowSize(ImVec2(320, 280));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.102f, 0.102f, 0.18f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.165f, 0.165f, 0.29f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoScrollbar;
    ImGui::Begin("##NotificationsPopup", nullptr, flags);

    ImGui::PushFont(uiFont_);
    ImGui::SetCursorPos(ImVec2(16, 12));
    ImGui::Text(ICON_FA_BELL " Notifications");
    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 80, 12));
    ImGui::PushStyleColor(ImGuiCol_Text, COL_RED);
    if (ImGui::SmallButton("Clear All")) {
        notifications_.clear();
        notificationCount_ = 0;
        notificationOpen_ = false;
    }
    ImGui::PopStyleColor();
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(0, 40));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.102f, 0.102f, 0.18f, 1.0f));
    ImGui::BeginChild("NotifList", ImVec2(320, 240), false);

    if (notifications_.empty()) {
        ImGui::SetCursorPos(ImVec2(16, 20));
        ImGui::PushFont(uiFont_);
        ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
        ImGui::Text(ICON_FA_CHECK_CIRCLE " No new notifications.");
        ImGui::PopStyleColor();
        ImGui::PopFont();
    } else {
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        ImVec2 wPos = ImGui::GetWindowPos();
        int idx = 0;
        for (auto it = notifications_.rbegin(); it != notifications_.rend(); ++it, ++idx) {
            float rowY = wPos.y + (float)idx * 68.0f;
            ImU32 accentCol = ImColor(it->color);

            drawList->AddRectFilled(ImVec2(wPos.x, rowY), ImVec2(wPos.x + 3, rowY + 68.0f), accentCol);
            drawList->AddCircleFilled(ImVec2(wPos.x + 22, rowY + 20), 14.0f,
                IM_COL32(0, 212, 255, 25));

            ImGui::SetCursorPos(ImVec2(44, 8 + (float)idx * 68.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT);
            ImGui::Text("%s", it->title.c_str());
            ImGui::PopStyleColor();
            ImGui::SetCursorPos(ImVec2(44, 26 + (float)idx * 68.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_MUTED);
            ImGui::SetWindowFontScale(0.85f);
            ImGui::Text("%s", it->message.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();

            float timeSec = (float)(ImGui::GetTime() - it->timestamp);
            std::string timeStr;
            if (timeSec < 60) timeStr = std::to_string((int)timeSec) + " secs ago";
            else timeStr = std::to_string((int)timeSec / 60) + " mins ago";
            ImGui::SetCursorPos(ImVec2(44, 44 + (float)idx * 68.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, COL_TEXT_DIM);
            ImGui::SetWindowFontScale(0.80f);
            ImGui::Text("%s", timeStr.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();

            if (idx < (int)notifications_.size() - 1) {
                drawList->AddLine(
                    ImVec2(wPos.x + 12, rowY + 67.0f),
                    ImVec2(wPos.x + 320 - 12, rowY + 67.0f),
                    IM_COL32(30, 30, 58, 255));
            }
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}
