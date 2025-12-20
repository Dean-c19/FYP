package org.example.cybermasterspring.dto;

public class ThreatStats {
    private final String label;
    private final int value;

    public ThreatStats(String label, int value) {
        this.label = label;
        this.value = value;
    }

    public String getLabel() {
        return label;
    }

    public int getValue() {
        return value;
    }
}
