#pragma once
#include "imgui.h"
#include "../../include/ImGuiColors.h"
#include "../../include/RuleEngine.h"
#include <vector>
#include <string>

class RulesPanel {
public:
    RulesPanel(RuleEngine* e) : engine_(e) {}
    void Render();
private:
    void RenderAddRulePopup();
    void RenderEditRulePopup();

    RuleEngine* engine_;
    bool showAddPopup_ = false;
    int newAction_ = 0;
    int newProtocol_ = 0;
    char newSrcIP_[64] = "";
    int newDestPort_ = 80;
    int newPriority_ = 100;

    int editRuleID_ = -1;
    bool showEditPopup_ = false;
    int editAction_ = 0;
    int editProtocol_ = 0;
    char editSrcIP_[64] = "";
    int editDestPort_ = 80;
    int editPriority_ = 100;
    bool showDeleteConfirm_ = false;
    int deleteRuleID_ = -1;
};
