package org.example.cybermasterspring.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.example.cybermasterspring.dto.ScanReportLLM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ScanReportLLMService {

    private static final Logger log = LoggerFactory.getLogger(ScanReportLLMService.class);

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final String openAiApiKey;
    private final String openAiModel;

    public ScanReportLLMService(ObjectMapper objectMapper,
                                @Value("${openai.api.key}") String openAiApiKey,
                                @Value("${openai.model}") String openAiModel) {
        this.objectMapper = objectMapper;
        this.restTemplate = new RestTemplate();
        this.openAiApiKey = openAiApiKey;
        this.openAiModel = openAiModel;
    }

    public ScanReportLLM buildLLMFields(String softwareName,
                                        String softwareVersion,
                                        int totalVulnerabilities,
                                        int highSeverity,
                                        int mediumSeverity,
                                        int lowSeverity,
                                        String overallRiskLevel,
                                        List<String> notableIssues) {
        log.info("OpenAI report generation started for software='{}' version='{}' risk='{}' totalVulnerabilities={}",
                softwareName, softwareVersion, overallRiskLevel, totalVulnerabilities);
        String prompt = buildPrompt(
                softwareName,
                softwareVersion,
                totalVulnerabilities,
                highSeverity,
                mediumSeverity,
                lowSeverity,
                overallRiskLevel,
                notableIssues
        );
        Map<String, Object> requestBody = buildRequestBody(prompt);
        String rawResponse = executeRequest(requestBody);
        log.info("OpenAI raw response received for software='{}' version='{}'", softwareName, softwareVersion);
        return parseResponse(rawResponse);
    }

    private String buildPrompt(String softwareName,
                               String softwareVersion,
                               int totalVulnerabilities,
                               int highSeverity,
                               int mediumSeverity,
                               int lowSeverity,
                               String overallRiskLevel,
                               List<String> notableIssues) {
        String safeSoftwareName = softwareName == null || softwareName.isBlank() ? "Unknown software" : softwareName;
        String safeSoftwareVersion = softwareVersion == null || softwareVersion.isBlank() ? "Unknown version" : softwareVersion;
        String issuesText = notableIssues == null || notableIssues.isEmpty()
                ? "No notable issues were selected."
                : String.join("\n- ", notableIssues);

        return """
                You are writing a vulnerability scan report.
                Use only the facts provided below.
                Do not invent CVEs, counts, affected versions, fixes, or technical details not present in the input.
                Return raw JSON only. Do not wrap the response in markdown or code fences.
                Return strict JSON only with these fields:
                intro: string
                riskImpact: array of strings
                recommendations: array of strings
                executiveSummary: string

                Writing guidance:
                - Write for a business and security audience in clear, professional language.
                - Make the intro specific to the software, version, vulnerability count and overall risk.
                - Return 2 to 5 riskImpact bullets that explain what the findings could mean in practice.
                - Return 2 to 5 recommendations bullets with practical remediation advice.
                - Prefer concise recommendations such as updating, patching, review or monitoring actions.
                - Only mention an exact fixed version if it is explicitly present in the facts below.
                - Keep the executiveSummary medium length, specific and action-oriented.

                Facts:
                Software: %s
                Version: %s
                Total vulnerabilities: %d
                High severity: %d
                Medium severity: %d
                Low severity: %d
                Overall risk level: %s
                Notable issues:
                - %s
                """.formatted(
                safeSoftwareName,
                safeSoftwareVersion,
                totalVulnerabilities,
                highSeverity,
                mediumSeverity,
                lowSeverity,
                overallRiskLevel,
                issuesText
        );
    }

    private Map<String, Object> buildRequestBody(String prompt) {
        Map<String, Object> inputText = new LinkedHashMap<>();
        inputText.put("type", "input_text");
        inputText.put("text", prompt);

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", "user");
        message.put("content", List.of(inputText));

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("model", openAiModel);
        requestBody.put("input", List.of(message));
        return requestBody;
    }

    private String executeRequest(Map<String, Object> requestBody) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(openAiApiKey);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(
                "https://api.openai.com/v1/responses",
                entity,
                String.class
        );
        log.debug("OpenAI HTTP status: {}", response.getStatusCode());
        return response.getBody();
    }

    private ScanReportLLM parseResponse(String rawResponse) {
        try {
            JsonNode root = objectMapper.readTree(rawResponse);
            String jsonText = extractOutputText(root);
            JsonNode llmNode = objectMapper.readTree(cleanJsonText(jsonText));

            String intro = llmNode.path("intro").asText("");
            String executiveSummary = llmNode.path("executiveSummary").asText("");
            List<String> riskImpact = readStringList(llmNode.path("riskImpact"));
            List<String> recommendations = readStringList(llmNode.path("recommendations"));

            log.info("OpenAI response parsed successfully");
            return new ScanReportLLM(intro, riskImpact, recommendations, executiveSummary);
        } catch (Exception e) {
            log.warn("OpenAI response parsing failed", e);
            throw new IllegalStateException("Failed to parse OpenAI response", e);
        }
    }

    private String cleanJsonText(String jsonText) {
        String cleaned = jsonText == null ? "" : jsonText.trim();
        if (cleaned.startsWith("```")) {
            cleaned = cleaned.replaceFirst("^```(?:json)?\\s*", "");
            cleaned = cleaned.replaceFirst("\\s*```$", "");
        }
        return cleaned.trim();
    }

    private String extractOutputText(JsonNode root) {
        JsonNode output = root.path("output");
        if (!output.isArray()) {
            throw new IllegalStateException("OpenAI response did not contain an output array");
        }

        for (JsonNode outputItem : output) {
            JsonNode content = outputItem.path("content");
            if (!content.isArray()) {
                continue;
            }
            for (JsonNode contentItem : content) {
                String type = contentItem.path("type").asText("");
                if ("output_text".equals(type)) {
                    String text = contentItem.path("text").asText("");
                    if (!text.isBlank()) {
                        return text;
                    }
                }
            }
        }

        throw new IllegalStateException("OpenAI response did not contain output text content");
    }

    private List<String> readStringList(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<String> values = new java.util.ArrayList<>();
        for (JsonNode item : node) {
            String value = item.asText("");
            if (!value.isBlank()) {
                values.add(value);
            }
        }
        return values;
    }
}
