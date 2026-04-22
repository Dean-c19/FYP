package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.ScanReportLLM;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ScanReportLLMService {

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
