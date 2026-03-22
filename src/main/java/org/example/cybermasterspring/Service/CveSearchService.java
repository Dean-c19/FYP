package org.example.cybermasterspring.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

@Service
public class CveSearchService {
    private static final String BASE_URL = "https://cve.circl.lu/api/search";
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<CveFinding> scan(List<SoftwareItem> items, boolean exactOnly) {
        List<CveFinding> findings = new ArrayList<>();
        for (SoftwareItem item : items) {
            String[] vendorProduct = deriveVendorProduct(item.getName());
            String vendor = vendorProduct[0];
            String product = vendorProduct[1];
            JsonNode root = fetchResults(vendor, product);
            JsonNode results = extractResults(root);
            if (results == null || !results.isArray() || results.isEmpty()) {
                continue;
            }
            int added = 0;
            for (JsonNode entry : results) {
                if (added >= 5) {
                    break;
                }
                JsonNode cve = extractCveNode(entry);
                if (cve == null) {
                    continue;
                }
                if (exactOnly && !matchesVersion(cve, item.getVersion())) {
                    continue;
                }
                String cveId = extractCveId(cve, entry);
                String summary = extractSummary(cve);
                Double cvss = extractCvss(cve);
                String published = extractPublished(cve);
                findings.add(new CveFinding(item.getName(), item.getVersion(), cveId, cvss, published, summary));
                added++;
            }
        }
        return findings;
    }

    private JsonNode fetchResults(String vendor, String product) {
        try {
            String url = UriComponentsBuilder.fromHttpUrl(BASE_URL)
                    .pathSegment(vendor, product)
                    .toUriString();
            String body = restTemplate.getForObject(url, String.class);
            if (body == null) {
                return null;
            }
            return objectMapper.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }

    private JsonNode extractResults(JsonNode root) {
        if (root == null) {
            return null;
        }
        JsonNode results = root.path("results");
        if (results.isObject()) {
            JsonNode nvd = results.get("nvd");
            if (nvd != null && nvd.isArray()) {
                return nvd;
            }
            JsonNode cvelistv5 = results.get("cvelistv5");
            if (cvelistv5 != null && cvelistv5.isArray()) {
                return cvelistv5;
            }
        }
        if (results.isArray()) {
            return results;
        }
        if (root.isArray()) {
            return root;
        }
        return null;
    }

    private JsonNode extractCveNode(JsonNode entry) {
        if (entry == null) {
            return null;
        }
        if (entry.isObject()) {
            return entry;
        }
        if (entry.isArray() && entry.size() >= 2 && entry.get(1).isObject()) {
            return entry.get(1);
        }
        return null;
    }

    private String extractCveId(JsonNode cve, JsonNode entry) {
        String id = cve.path("id").asText(null);
        if (id != null && !id.isBlank()) {
            return id.toUpperCase();
        }
        id = cve.path("cveMetadata").path("cveId").asText(null);
        if (id != null && !id.isBlank()) {
            return id.toUpperCase();
        }
        if (entry != null && entry.isArray() && entry.size() >= 1) {
            String fromEntry = entry.get(0).asText(null);
            if (fromEntry != null && !fromEntry.isBlank()) {
                return fromEntry.toUpperCase();
            }
        }
        return "UNKNOWN";
    }

    private String extractSummary(JsonNode cve) {
        String summary = cve.path("summary").asText(null);
        if (summary != null && !summary.isBlank()) {
            return summary;
        }
        JsonNode cnaDescriptions = cve.path("containers").path("cna").path("descriptions");
        if (cnaDescriptions.isArray() && cnaDescriptions.size() > 0) {
            String val = cnaDescriptions.get(0).path("value").asText(null);
            if (val != null) {
                return val;
            }
        }
        JsonNode nvdDescriptions = cve.path("descriptions");
        if (nvdDescriptions.isArray() && nvdDescriptions.size() > 0) {
            String val = nvdDescriptions.get(0).path("value").asText(null);
            if (val != null) {
                return val;
            }
        }
        return "";
    }

    private Double extractCvss(JsonNode cve) {
        if (cve.hasNonNull("cvss")) {
            return cve.get("cvss").asDouble();
        }
        JsonNode cvssMetricV31 = cve.path("metrics").path("cvssMetricV31");
        if (cvssMetricV31.isArray() && cvssMetricV31.size() > 0) {
            JsonNode baseScore = cvssMetricV31.get(0).path("cvssData").path("baseScore");
            if (baseScore.isNumber()) {
                return baseScore.asDouble();
            }
        }
        JsonNode adp = cve.path("containers").path("adp");
        if (adp.isArray()) {
            for (JsonNode adpNode : adp) {
                JsonNode metrics = adpNode.path("metrics");
                if (metrics.isArray() && metrics.size() > 0) {
                    JsonNode cvss = metrics.get(0).path("cvssV3_1").path("baseScore");
                    if (cvss.isNumber()) {
                        return cvss.asDouble();
                    }
                }
            }
        }
        return null;
    }

    private String extractPublished(JsonNode cve) {
        String published = cve.path("Published").asText(null);
        if (published != null && !published.isBlank()) {
            return formatDate(published);
        }
        published = cve.path("published").asText(null);
        if (published != null && !published.isBlank()) {
            return formatDate(published);
        }
        return formatDate(cve.path("cveMetadata").path("datePublished").asText(""));
    }

    private String formatDate(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        try {
            if (raw.contains("T")) {
                return OffsetDateTime.parse(raw).format(DateTimeFormatter.ofPattern("dd-MM-yyyy"));
            }
            return LocalDate.parse(raw).format(DateTimeFormatter.ofPattern("dd-MM-yyyy"));
        } catch (DateTimeParseException e) {
            return raw;
        }
    }

    private boolean matchesVersion(JsonNode cve, String version) {
        if (version == null || version.isBlank()) {
            return true;
        }
        String v = version.trim();
        JsonNode affected = cve.path("containers").path("cna").path("affected");
        if (affected.isArray()) {
            for (JsonNode a : affected) {
                JsonNode versions = a.path("versions");
                if (versions.isArray()) {
                    for (JsonNode ver : versions) {
                        String verValue = ver.path("version").asText("");
                        if (verValue.contains(v)) {
                            return true;
                        }
                        String lessThan = ver.path("lessThan").asText("");
                        if (lessThan.contains(v)) {
                            return true;
                        }
                    }
                }
            }
        }
        String summary = extractSummary(cve);
        return summary.contains(v);
    }

    private String[] deriveVendorProduct(String name) {
        String normalized = name == null ? "" : name.trim().toLowerCase();
        if (normalized.isEmpty()) {
            return new String[] {"unknown", "unknown"};
        }
        if (normalized.contains(" ")) {
            String[] parts = normalized.split("\\s+");
            String vendor = parts[0];
            String product = String.join("_", java.util.Arrays.copyOfRange(parts, 1, parts.length));
            return new String[] { vendor, product };
        }
        return new String[] { normalized, normalized };
    }
}
