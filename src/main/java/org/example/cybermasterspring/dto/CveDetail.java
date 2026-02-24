package org.example.cybermasterspring.dto;

public class CveDetail {
    private final String cveId;
    private final String description;
    private final String baseScore;

    public CveDetail(String cveId, String description, String baseScore) {
        this.cveId = cveId;
        this.description = description;
        this.baseScore = baseScore;
    }

    public String getCveId() { return cveId; }
    public String getDescription() { return description; }
    public String getBaseScore() { return baseScore; }
}
