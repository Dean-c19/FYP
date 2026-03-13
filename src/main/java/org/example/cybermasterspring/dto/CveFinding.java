package org.example.cybermasterspring.dto;

public class CveFinding {
    private final String softwareName;
    private final String softwareVersion;
    private final String cveId;
    private final Double cvss;
    private final String published;
    private final String summary;

    public CveFinding(String softwareName, String softwareVersion, String cveId, Double cvss, String published, String summary) {
        this.softwareName = softwareName;
        this.softwareVersion = softwareVersion;
        this.cveId = cveId;
        this.cvss = cvss;
        this.published = published;
        this.summary = summary;
    }

    public String getSoftwareName() { return softwareName; }
    public String getSoftwareVersion() { return softwareVersion; }
    public String getCveId() { return cveId; }
    public Double getCvss() { return cvss; }
    public String getPublished() { return published; }
    public String getSummary() { return summary; }
}
