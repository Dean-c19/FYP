package org.example.cybermasterspring.service;

import com.rometools.rome.feed.synd.SyndEntry;
import com.rometools.rome.feed.synd.SyndFeed;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.io.XmlReader;
import org.jdom2.Element;
import org.example.cybermasterspring.dto.CyberNews;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Service
public class CyberNewsService {
    private static final String FEED_URL = "https://thehackernews.com/feeds/posts/default";

    public List<CyberNews> getLatest(int limit) {
        List<CyberNews> items = new ArrayList<>();
        try (XmlReader reader = new XmlReader(new URL(FEED_URL))) {
            SyndFeed feed = new SyndFeedInput().build(reader);
            List<SyndEntry> entries = feed.getEntries();
            int max = Math.min(limit, entries.size());
            for (int i = 0; i < max; i++) {
                SyndEntry entry = entries.get(i);
                String imageUrl = extractImageUrl(entry);
                items.add(new CyberNews(
                        entry.getTitle(),
                        entry.getLink(),
                        entry.getPublishedDate(),
                        imageUrl
                ));
            }
        } catch (Exception ignored) {

        }
        return items;
    }

    private String extractImageUrl(SyndEntry entry) {
        if (entry.getEnclosures() != null) {
            for (var enclosure : entry.getEnclosures()) {
                if (enclosure.getType() != null && enclosure.getType().startsWith("image/")) {
                    return enclosure.getUrl();
                }
            }
        }

        List<Element> foreign = entry.getForeignMarkup();
        if (foreign != null) {
            for (Element el : foreign) {
                String name = el.getName();
                if ("thumbnail".equalsIgnoreCase(name) || "content".equalsIgnoreCase(name) || "image".equalsIgnoreCase(name)) {
                    String url = el.getAttributeValue("url");
                    if (url == null) {
                        url = el.getAttributeValue("href");
                    }
                    if (url != null && !url.isBlank()) {
                        return url;
                    }
                }
            }
        }

        return null;
    }
}
