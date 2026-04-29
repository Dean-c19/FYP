package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.ScanReportLLM;
import org.example.cybermasterspring.dto.ScanReport;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;

@Service
public class ScanReportService {

    private static final Logger log = LoggerFactory.getLogger(ScanReportService.class);

    private final ScanReportLLMService scanReportLLMService;

    public ScanReportService(ScanReportLLMService scanReportLLMService) {
        this.scanReportLLMService = scanReportLLMService;
    }

    public ScanReport buildReport(List<SoftwareItem> parsedItems, List<CveFinding> findings) {
        String title = "Vulnerability Scan Summary";
        if (!parsedItems.isEmpty()) {
            SoftwareItem firstItem = parsedItems.get(0);
            title = "Vulnerability Scan Summary - " + firstItem.getName() + " (" + firstItem.getVersion() + ")";
        }

        String intro;
        if (findings.isEmpty()) {
            intro = "No matching vulnerabilities were identified for the submitted software list.";
        } else {
            intro = "This scan identified " + findings.size() + " known vulnerabilities affecting the submitted software.";
        }

        int highSeverity = 0;
        int mediumSeverity = 0;
        int lowSeverity = 0;
        double maxCvss = -1.0;
        boolean hasScoredFinding = false;

        for (CveFinding finding : findings) {
            Double cvss = finding.getCvss();
            if (cvss == null) {
                continue;
            }
            hasScoredFinding = true;
            if (cvss > maxCvss) {
                maxCvss = cvss;
            }
            if (cvss >= 7.0) {
                highSeverity++;
            } else if (cvss >= 4.0) {
                mediumSeverity++;
            } else {
                lowSeverity++;
            }
        }

        String overallRiskLevel;
        if (maxCvss >= 7.0) {
            overallRiskLevel = "High";
        } else if (maxCvss >= 4.0) {
            overallRiskLevel = "Medium";
        } else if (!findings.isEmpty() && !hasScoredFinding) {
            overallRiskLevel = "Unknown";
        } else if (!findings.isEmpty()) {
            overallRiskLevel = "Low";
        } else {
            overallRiskLevel = "None";
        }

        List<String> notableIssues = findings.stream()
                .sorted(Comparator.comparing(
                        (CveFinding finding) -> finding.getCvss() == null ? -1.0 : finding.getCvss()
                ).reversed())
                .limit(3)
                .map(finding -> {
                    String cvssText = finding.getCvss() == null ? "N/A" : String.valueOf(finding.getCvss());
                    String summary = finding.getSummary() == null ? "No summary available." : finding.getSummary();
                    return finding.getCveId()
                            + " (" + finding.getSoftwareName() + " - CVSS " + cvssText + "): "
                            + summary;
                })
                .toList();

        String softwareName = parsedItems.isEmpty() ? "" : parsedItems.get(0).getName();
       String softwareVersion = parsedItems.isEmpty() ? "" : parsedItems.get(0).getVersion();
        ScanReportLLM llmFields;
        try {
            llmFields = scanReportLLMService.buildLLMFields(
                    softwareName,
                    softwareVersion,
                    findings.size(),
                    highSeverity,
                    mediumSeverity,
                    lowSeverity,
                    overallRiskLevel,
                    notableIssues
            );
        } catch (RuntimeException e) {
            log.warn("Falling back to local report wording because OpenAI generation failed", e);
            llmFields = null;
        }
        if (llmFields == null) {
            llmFields = buildFallbackLLMFields(
                    softwareName,
                    softwareVersion,
                    findings.size(),
                    overallRiskLevel,
                    notableIssues
            );
        }

        return new ScanReport(
                title,
                llmFields.getIntro(),
                findings.size(),
                highSeverity,
                mediumSeverity,
                lowSeverity,
                overallRiskLevel,
                notableIssues,
                llmFields.getRiskImpact(),
                llmFields.getRecommendations(),
                llmFields.getExecutiveSummary()
        );
    }

    private ScanReportLLM buildFallbackLLMFields(String softwareName,
                                                 String softwareVersion,
                                                 int totalVulnerabilities,
                                                 String overallRiskLevel,
                                                 List<String> notableIssues) {
        String displayName = softwareName == null || softwareName.isBlank() ? "the scanned software" : softwareName;
        String displayVersion = softwareVersion == null || softwareVersion.isBlank() ? "unknown version" : softwareVersion;

        String intro;
        if (totalVulnerabilities == 0) {
            intro = "The scan of " + displayName + " (" + displayVersion + ") did not identify matching vulnerabilities in the current results.";
        } else {
            intro = "The scan of " + displayName + " (" + displayVersion + ") identified "
                    + totalVulnerabilities + " known vulnerabilities. The current overall risk level is "
                    + overallRiskLevel + ".";
        }

        List<String> riskImpact;
        if ("High".equals(overallRiskLevel)) {
            riskImpact = List.of(
                    "These vulnerabilities may allow code execution, memory corruption or unauthorized access depending on exploit conditions.",
                    "Successful exploitation could affect system confidentiality, integrity or availability.",
                    "Attack paths may include malicious websites, downloads or crafted files."
            );
        } else if ("Medium".equals(overallRiskLevel)) {
            riskImpact = List.of(
                    "These vulnerabilities may allow browser instability, information disclosure or bypass of some security controls.",
                    "Exploitation may still be practical in real-world web or file-based attack scenarios."
            );
        } else if ("Low".equals(overallRiskLevel)) {
            riskImpact = List.of(
                    "The identified issues appear lower risk but they still weaken the software security posture."
            );
        } else if ("Unknown".equals(overallRiskLevel)) {
            riskImpact = List.of(
                    "Vulnerabilities were identified, but severity scoring was not available in the current results.",
                    "The findings should still be reviewed because unscored issues can include meaningful security impact."
            );
        } else {
            riskImpact = List.of(
                    "No direct vulnerability impact was identified from the current scan results."
            );
        }

        List<String> recommendations;
        if ("None".equals(overallRiskLevel)) {
            recommendations = List.of(
                    "No immediate remediation action is indicated by the current results.",
                    "Continue regular patching and repeat scans when software versions change."
            );
        } else if ("Unknown".equals(overallRiskLevel)) {
            recommendations = List.of(
                    "Review the identified findings manually because severity scoring was unavailable.",
                    "Check vendor advisories and supported versions to assess remediation priority.",
                    "Apply updates or compensating controls where the affected component is still in use."
            );
        } else {
            recommendations = List.of(
                    "Update the affected software to the latest available version.",
                    "Enable automatic updates where possible.",
                    "Avoid opening untrusted files, downloads or links.",
                    "Use endpoint protection and routine patch management."
            );
        }

        String executiveSummary;
        if (totalVulnerabilities == 0) {
            executiveSummary = "This scan did not identify matching vulnerabilities for " + displayName
                    + " (" + displayVersion + ") in the current dataset.";
        } else if ("Unknown".equals(overallRiskLevel)) {
            executiveSummary = displayName + " (" + displayVersion + ") has " + totalVulnerabilities
                    + " matched vulnerabilities, but severity scoring was unavailable in the current results."
                    + " The findings should be reviewed manually to determine remediation priority.";
        } else {
            String topIssue = notableIssues.isEmpty() ? "the identified findings" : notableIssues.get(0);
            executiveSummary = displayName + " (" + displayVersion + ") currently presents a "
                    + overallRiskLevel.toLowerCase() + " security risk based on " + totalVulnerabilities
                    + " matched vulnerabilities. Immediate attention should focus on " + topIssue + ".";
        }

        return new ScanReportLLM(intro, riskImpact, recommendations, executiveSummary);
    }
}
