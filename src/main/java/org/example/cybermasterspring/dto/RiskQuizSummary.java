package org.example.cybermasterspring.dto;

import java.time.LocalDateTime;
import java.util.List;

public class RiskQuizSummary {

    private final int totalScore;
    private final String riskLevel;
    private final LocalDateTime completedAt;
    private final List<String> recommendations;

    public RiskQuizSummary(int totalScore,
                           String riskLevel,
                           LocalDateTime completedAt,
                           List<String> recommendations) {
        this.totalScore = totalScore;
        this.riskLevel = riskLevel;
        this.completedAt = completedAt;
        this.recommendations = recommendations;
    }

    public int getTotalScore() {
        return totalScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public LocalDateTime getCompletedAt() {
        return completedAt;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }
}
