package org.example.cybermasterspring.dto;

import java.util.List;

public class ScanReportLLM {

    private final String intro;
    private final List<String> riskImpact;
    private final List<String> recommendations;
    private final String executiveSummary;

    public ScanReportLLM(String intro,
                         List<String> riskImpact,
                         List<String> recommendations,
                         String executiveSummary) {
        this.intro = intro;
        this.riskImpact = riskImpact;
        this.recommendations = recommendations;
        this.executiveSummary = executiveSummary;
    }

    public String getIntro() {
        return intro;
    }

    public List<String> getRiskImpact() {
        return riskImpact;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    public String getExecutiveSummary() {
        return executiveSummary;
    }
}
