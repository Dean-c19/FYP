package org.example.cybermasterspring.dto;

import java.time.LocalDateTime;
import java.util.List;

public class ScanHistoryItem {

    private final Long id;
    private final String username;
    private final LocalDateTime scannedAt;
    private final boolean exactOnly;
    private final List<ScanHistorySoftware> softwareItems;
    private final List<ScanHistoryFinding> findings;
    private final ScanHistoryReport report;

    public ScanHistoryItem(Long id,
                           String username,
                           LocalDateTime scannedAt,
                           boolean exactOnly,
                           List<ScanHistorySoftware> softwareItems,
                           List<ScanHistoryFinding> findings,
                           ScanHistoryReport report) {
        this.id = id;
        this.username = username;
        this.scannedAt = scannedAt;
        this.exactOnly = exactOnly;
        this.softwareItems = softwareItems;
        this.findings = findings;
        this.report = report;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public boolean isExactOnly() {
        return exactOnly;
    }

    public List<ScanHistorySoftware> getSoftwareItems() {
        return softwareItems;
    }

    public List<ScanHistoryFinding> getFindings() {
        return findings;
    }

    public ScanHistoryReport getReport() {
        return report;
    }
}
