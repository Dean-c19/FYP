package org.example.cybermasterspring.dto;

import java.util.List;

public class ScanReport {

    private final String title;
    private final String intro;
    private final int totalVulnerabilities;
    private final int highSeverity;
    private final int mediumSeverity;
    private final int lowSeverity;
    private final String overallRiskLevel;
    private final List<String> notableIssues;
    private final List<String> riskImpact;
    private final List<String> recommendations;
    private final String executiveSummary;

    public ScanReport(String title,
                      String intro,
                      int totalVulnerabilities,
                      int highSeverity,
                      int mediumSeverity,
                      int lowSeverity,
                      String overallRiskLevel,
                      List<String> notableIssues,
                      List<String> riskImpact,
                      List<String> recommendations,
                      String executiveSummary) {
        this.title = title;
        this.intro = intro;
        this.totalVulnerabilities = totalVulnerabilities;
        this.highSeverity = highSeverity;
        this.mediumSeverity = mediumSeverity;
        this.lowSeverity = lowSeverity;
        this.overallRiskLevel = overallRiskLevel;
        this.notableIssues = notableIssues;
        this.riskImpact = riskImpact;
        this.recommendations = recommendations;
        this.executiveSummary = executiveSummary;
    }

    public String getTitle() {
        return title;
    }

    public String getIntro() {
        return intro;
    }

    public int getTotalVulnerabilities() {
        return totalVulnerabilities;
    }

    public int getHighSeverity() {
        return highSeverity;
    }

    public int getMediumSeverity() {
        return mediumSeverity;
    }

    public int getLowSeverity() {
        return lowSeverity;
    }

    public String getOverallRiskLevel() {
        return overallRiskLevel;
    }

    public List<String> getNotableIssues() {
        return notableIssues;
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
