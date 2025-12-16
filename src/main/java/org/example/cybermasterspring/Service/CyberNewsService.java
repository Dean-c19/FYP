package org.example.cybermasterspring.service;

import com.rometools.rome.feed.synd.SyndEntry;
import com.rometools.rome.feed.synd.SyndFeed;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.io.XmlReader;
import org.example.cybermasterspring.dto.CyberNews;
import org.example.cybermasterspring.dto.CyberNewsArticle;
import org.springframework.stereotype.Service;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

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

    public CyberNewsArticle getArticleSummary(String url) {
        try {
            Document doc = Jsoup.connect(url)
                    .userAgent("Mozilla/5.0 (CyberMaster)")
                    .timeout(8000)
                    .get();

            String title = doc.title();
            String imageUrl = extractOgImage(doc);
            List<String> summary = extractSummaryParagraphs(doc, 3);

            return new CyberNewsArticle(title, imageUrl, summary, url);
        } catch (Exception ignored) {
            return new CyberNewsArticle("Article unavailable", null, List.of(), url);
        }
    }

    private String extractImageUrl(SyndEntry entry) {
        if (entry.getEnclosures() != null) {
            for (var enclosure : entry.getEnclosures()) {
                if (enclosure.getType() != null && enclosure.getType().startsWith("image/")) {
                    return enclosure.getUrl();
                }
            }
        }

        List<org.jdom2.Element> foreign = entry.getForeignMarkup();
        if (foreign != null) {
            for (org.jdom2.Element el : foreign) {
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

    private String extractOgImage(Document doc) {
        Element og = doc.selectFirst("meta[property=og:image], meta[name=og:image]");
        if (og != null) {
            String content = og.attr("content");
            if (content != null && !content.isBlank()) {
                return content;
            }
        }
        return null;
    }

    private List<String> extractSummaryParagraphs(Document doc, int limit) {
        List<String> paragraphs = new ArrayList<>();
        Elements candidates = doc.select("article p");
        if (candidates.isEmpty()) {
            candidates = doc.select(".articlebody p");
        }
        if (candidates.isEmpty()) {
            candidates = doc.select("p");
        }

        for (Element p : candidates) {
            String text = p.text().trim();
            if (text.length() < 30) {
                continue;
            }
            paragraphs.add(text);
            if (paragraphs.size() >= limit) {
                break;
            }
        }

        return paragraphs;
    }
}
