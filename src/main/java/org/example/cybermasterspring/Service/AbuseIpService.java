package org.example.cybermasterspring.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.ThreatEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AbuseIpService {
    private static final String BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist";
    private static final Duration CACHE_TTL = Duration.ofHours(6);

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final GeoIpService geoIpService;
    private final String apiKey;

    private Instant lastFetchedAt = Instant.EPOCH;
    private List<ThreatEvent> cached = List.of();

    public AbuseIpService(GeoIpService geoIpService, @Value("${abuseipdb.api.key:}") String apiKey) {
        this.geoIpService = geoIpService;
        this.apiKey = apiKey;
    }

    public List<ThreatEvent> getThreatEvents() {
        if (Instant.now().isBefore(lastFetchedAt.plus(CACHE_TTL)) && !cached.isEmpty()) {
            return cached;
        }
        if (apiKey == null || apiKey.isBlank()) {
            return List.of();
        }

        try {
            String url = UriComponentsBuilder.fromHttpUrl(BASE_URL)
                    .queryParam("confidenceMinimum", 75)
                    .queryParam("limit", 200)
                    .toUriString();

            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", apiKey);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String body = restTemplate.exchange(url, HttpMethod.GET, entity, String.class).getBody();
            if (body == null) {
                return cached;
            }

            JsonNode root = objectMapper.readTree(body);
            JsonNode data = root.get("data");
            if (data == null || !data.isArray()) {
                return cached;
            }

            List<ThreatEvent> events = new ArrayList<>();
            for (JsonNode item : data) {
                String ip = item.path("ipAddress").asText(null);
                int score = item.path("abuseConfidenceScore").asInt(0);
                if (ip == null) continue;
                Optional<GeoIpService.GeoPoint> geo = geoIpService.lookup(ip);
                if (geo.isEmpty()) continue;
                GeoIpService.GeoPoint point = geo.get();
                events.add(new ThreatEvent(ip, point.getLat(), point.getLng(), point.getCountry(), score));
            }

            cached = events;
            lastFetchedAt = Instant.now();
            return cached;
        } catch (Exception e) {
            return cached;
        }
    }
}
