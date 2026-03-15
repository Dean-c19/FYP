package org.example.cybermasterspring.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.List;

@Service
public class CveSearchService {
    private static final String BASE_URL = "https://cve.circl.lu/api/search";
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<CveFinding> scan(List<SoftwareItem> items) {
        for (SoftwareItem item : items) {
            String[] vendorProduct = deriveVendorProduct(item.getName());
            String vendor = vendorProduct[0];
            String product = vendorProduct[1];
            fetchResults(vendor, product);
        }
        return Collections.emptyList();
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
