package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.ScanReportLLM;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ScanReportLLMService {

    private final String openAiApiKey;
    private final String openAiModel;

    public ScanReportLLMService(@Value("${openai.api.key}") String openAiApiKey,
                                @Value("${openai.model}") String openAiModel) {
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
        return null;
    }
}
