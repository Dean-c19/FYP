package org.example.cybermasterspring.dto;

public class CveTrendItem {
    private final String cveId;
    private final String title;
    private final String link;

    public CveTrendItem(String cveId, String title, String link) {
        this.cveId = cveId;
        this.title = title;
        this.link = link;
    }

    public String getCveId() { return cveId; }
    public String getTitle() { return title; }
    public String getLink() { return link; }
}
