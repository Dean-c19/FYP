package org.example.cybermasterspring.dto;

import java.util.List;

public class CyberNewsArticle {
    private final String title;
    private final String imageUrl;
    private final List<String> summaryParagraphs;
    private final String sourceUrl;

    public CyberNewsArticle(String title, String imageUrl, List<String> summaryParagraphs, String sourceUrl) {
        this.title = title;
        this.imageUrl = imageUrl;
        this.summaryParagraphs = summaryParagraphs;
        this.sourceUrl = sourceUrl;
    }

    public String getTitle() {
        return title;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public List<String> getSummaryParagraphs() {
        return summaryParagraphs;
    }

    public String getSourceUrl() {
        return sourceUrl;
    }
}
