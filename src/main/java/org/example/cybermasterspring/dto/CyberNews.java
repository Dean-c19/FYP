package org.example.cybermasterspring.dto;

import java.util.Date;

public class CyberNews {
    private final String title;
    private final String link;
    private final Date publishedAt;

    public CyberNews(String title, String link, Date publishedAt) {
        this.title = title;
        this.link = link;
        this.publishedAt = publishedAt;
    }

    public String getTitle() {
        return title;
    }

    public String getLink() {
        return link;
    }

    public Date getPublishedAt() {
        return publishedAt;
    }
}
