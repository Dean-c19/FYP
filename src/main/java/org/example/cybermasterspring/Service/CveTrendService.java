package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.CveTrendItem;
import org.example.cybermasterspring.dto.CveDetail;
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

    public CveDetail getCveDetail(String cveId) {
        try {
            String url = "https://cveinfo.com/detail.php?id=" + cveId;
            Document doc = Jsoup.connect(url)
                    .userAgent("Mozilla/5.0 (CyberMaster)")
                    .timeout(8000)
                    .get();

            String description = valueByLabel(doc, "Vulnerability Description");
            if (description.isBlank()) {
                description = valueByLabelContains(doc, "Vulnerability Description");
            }
            if (description.isBlank()) {
                Element meta = doc.selectFirst("meta[name=description]");
                if (meta != null) {
                    String metaDesc = meta.attr("content").trim();
                    if (!metaDesc.isBlank()) {
                        description = metaDesc;
                    }
                }
            }
            if (description.isBlank()) {
                Element descEl = doc.selectFirst("#vuln_description, #vulnerability_description, .vuln_description, .vulnerability_description");
                if (descEl != null) {
                    String txt = descEl.text().trim();
                    if (!txt.isBlank() && !txt.toLowerCase().contains("no comments")) {
                        description = txt;
                    }
                }
            }

            String baseScore = valueByLabel(doc, "Base Score");
            if (baseScore.isBlank()) {
                Element score = doc.selectFirst(".cvssscore, #cvssscore, .cvss, .score");
                if (score != null) baseScore = score.text().trim();
            }

            return new CveDetail(
                    cveId,
                    description.isBlank() ? "No description available." : description,
                    baseScore
            );
        } catch (Exception e) {
            return new CveDetail(cveId, "No description available.", "");
        }
    }

    private String valueByLabel(Document doc, String label) {
        String labelLower = label.toLowerCase();
        for (Element row : doc.select("tr")) {
            Elements cells = row.select("th, td");
            if (cells.size() >= 2) {
                String first = cells.get(0).text().trim().toLowerCase();
                if (first.equals(labelLower)) {
                    String val = cells.get(1).text().trim();
                    if (!val.isBlank()) {
                        return val;
                    }
                }
            }
        }

        for (Element el : doc.select("th, td, dt, div, span, b, strong")) {
            String text = el.text().trim();
            if (text.equalsIgnoreCase(label) || text.toLowerCase().contains(labelLower)) {
                Element next = el.nextElementSibling();
                if (next != null && !next.text().isBlank()) {
                    return next.text().trim();
                }
            }
        }
        return "";
    }

    private String valueByLabelContains(Document doc, String label) {
        String labelLower = label.toLowerCase();
        for (Element row : doc.select("tr")) {
            Elements cells = row.select("th, td");
            if (cells.size() >= 2) {
                String first = cells.get(0).text().trim().toLowerCase();
                if (first.contains(labelLower)) {
                    String val = cells.get(1).text().trim();
                    if (!val.isBlank()) {
                        return val;
                    }
                }
            }
        }
        return "";
    }
}
