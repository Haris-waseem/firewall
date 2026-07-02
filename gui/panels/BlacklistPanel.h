#pragma once
#include "imgui.h"
#include "../../include/ImGuiColors.h"
#include "../../include/RuleEngine.h"

class BlacklistPanel {
public:
    BlacklistPanel(RuleEngine* e) : engine_(e) {}
    void Render();
private:
    RuleEngine* engine_;
    char newIP_[64] = "";
    int selectedTab_ = 0;
};


