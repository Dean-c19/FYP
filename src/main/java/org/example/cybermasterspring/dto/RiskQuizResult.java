package org.example.cybermasterspring.dto;

import java.util.Map;

public class RiskQuizResult {

    private final int totalScore;
    private final String riskLevel;
    private final Map<String, Integer> categoryScores;
    private final Map<String, String> answers;

    public RiskQuizResult(int totalScore,
                          String riskLevel,
                          Map<String, Integer> categoryScores,
                          Map<String, String> answers) {
        this.totalScore = totalScore;
        this.riskLevel = riskLevel;
        this.categoryScores = categoryScores;
        this.answers = answers;
    }

    public int getTotalScore() {
        return totalScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public Map<String, Integer> getCategoryScores() {
        return categoryScores;
    }

    public Map<String, String> getAnswers() {
        return answers;
    }
}
