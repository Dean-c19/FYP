package org.example.cybermasterspring.dto;

import java.util.Date;

public class CyberNews {
    private final String title;
    private final String link;
    private final Date publishedAt;
    private final String imageUrl;

    public CyberNews(String title, String link, Date publishedAt, String imageUrl) {
        this.title = title;
        this.link = link;
        this.publishedAt = publishedAt;
        this.imageUrl = imageUrl;
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

    public String getImageUrl() {
        return imageUrl;
    }
}
