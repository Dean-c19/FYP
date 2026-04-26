package org.example.cybermasterspring.dto;

import java.util.List;

public class RiskQuizQuestion {

    private String id;
    private String text;
    private String category;
    private String type;
    private List<RiskQuizOption> options;
    private List<RiskQuizCondition> showIf;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<RiskQuizOption> getOptions() {
        return options;
    }

    public void setOptions(List<RiskQuizOption> options) {
        this.options = options;
    }

    public List<RiskQuizCondition> getShowIf() {
        return showIf;
    }

    public void setShowIf(List<RiskQuizCondition> showIf) {
        this.showIf = showIf;
    }
}
