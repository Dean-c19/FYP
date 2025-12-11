package org.example.cybermasterspring.service;

import com.rometools.rome.feed.synd.SyndEntry;
import com.rometools.rome.feed.synd.SyndFeed;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.io.XmlReader;
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
                items.add(new CyberNews(
                        entry.getTitle(),
                        entry.getLink(),
                        entry.getPublishedDate()
                ));
            }
        } catch (Exception ignored) {

        }
        return items;
    }
}
