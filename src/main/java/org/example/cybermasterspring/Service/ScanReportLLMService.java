package org.example.cybermasterspring.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.ScanReportLLM;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ScanReportLLMService {

    private final ObjectMapper objectMapper;
    private final String openAiApiKey;
    private final String openAiModel;

    public ScanReportLLMService(ObjectMapper objectMapper,
                                @Value("${openai.api.key}") String openAiApiKey,
                                @Value("${openai.model}") String openAiModel) {
        this.objectMapper = objectMapper;
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
        return null;
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
                Return strict JSON only with these fields:
                intro: string
                riskImpact: array of strings
                recommendations: array of strings
                executiveSummary: string

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
        Map<String, Object> textFormat = new LinkedHashMap<>();
        textFormat.put("type", "json_object");

        Map<String, Object> inputText = new LinkedHashMap<>();
        inputText.put("type", "input_text");
        inputText.put("text", prompt);

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", "user");
        message.put("content", List.of(inputText));

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("model", openAiModel);
        requestBody.put("input", List.of(message));
        requestBody.put("text", textFormat);
        return requestBody;
    }
}
