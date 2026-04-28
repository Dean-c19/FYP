package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.CveTrendItem;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class CveTrendService {
    private static final String TRENDS_URL = "https://cveinfo.com/trends.php";
    private static final Duration CACHE_TTL = Duration.ofHours(6);

    private Instant lastFetchedAt = Instant.EPOCH;
    private List<CveTrendItem> cached = List.of();

    public List<CveTrendItem> getRecentlyPublished(int limit) {
        if (Instant.now().isBefore(lastFetchedAt.plus(CACHE_TTL)) && !cached.isEmpty()) {
            return cached.subList(0, Math.min(limit, cached.size()));
        }

        try {
            Document doc = Jsoup.connect(TRENDS_URL)
                    .userAgent("Mozilla/5.0 (CyberMaster)")
                    .timeout(8000)
                    .get();

            List<CveTrendItem> items = new ArrayList<>();
            Element section = findSectionByHeading(doc, "Recently Published CVEs");
            Elements links = section != null ? section.select("a[href*='CVE-']") : new Elements();

            if (links.isEmpty()) {
                links = doc.select("a[href*='CVE-'], a:matchesOwn(CVE-\\d{4}-\\d+)");
            }

            for (Element link : links) {
                String text = link.text().trim();
                String href = link.absUrl("href");
                String cveId = extractCveId(text.isEmpty() ? href : text);
                if (cveId == null) continue;
                String title = text.isEmpty() ? cveId : text;
                items.add(new CveTrendItem(cveId, title, href.isEmpty() ? "https://cveinfo.com/" : href));
                if (items.size() >= limit) break;
            }

            cached = items;
            lastFetchedAt = Instant.now();
            return items;
        } catch (Exception e) {
            return cached;
        }
    }

    private Element findSectionByHeading(Document doc, String heading) {
        for (Element h : doc.select("h2, h3, h4")) {
            if (heading.equalsIgnoreCase(h.text().trim())) {
                Element parent = h.parent();
                return parent != null ? parent : doc;
            }
        }
        return null;
    }

    private String extractCveId(String text) {
        String upper = text.toUpperCase();
        int idx = upper.indexOf("CVE-");
        if (idx == -1) return null;
        int end = Math.min(upper.length(), idx + 15);
        return upper.substring(idx, end).replaceAll("[^A-Z0-9-]", "");
    }
}
