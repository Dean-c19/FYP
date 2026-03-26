package org.example.cybermasterspring.dto;

public class ScanHistorySoftware {

    private final String softwareName;
    private final String softwareVersion;

    public ScanHistorySoftware(String softwareName, String softwareVersion) {
        this.softwareName = softwareName;
        this.softwareVersion = softwareVersion;
    }

    public String getSoftwareName() {
        return softwareName;
    }

    public String getSoftwareVersion() {
        return softwareVersion;
    }
}
