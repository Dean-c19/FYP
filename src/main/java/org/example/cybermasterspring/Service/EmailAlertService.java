package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.ScanReport;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmailAlertService {

    private final JavaMailSender mailSender;

    // this service sends email alerts when a finished scan contains high severitys
    public EmailAlertService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    // when a high risk is detected this creates and then sends the alert email using the report data
    public void sendHighRiskScanAlert(String recipientEmail,
                                      String softwareName,
                                      String softwareVersion,
                                      ScanReport report) {
        String subject = "IMPORTANT: High-Risk Vulnerability Detected in Your Scan";
        String body = buildHighRiskScanBody(softwareName, softwareVersion, report);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(recipientEmail);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }

    // this turns the report object into the plain text email body to be sent to the user
    private String buildHighRiskScanBody(String softwareName,
                                         String softwareVersion,
                                         ScanReport report) {
        String safeSoftwareName = softwareName == null || softwareName.isBlank() ? "Unknown software" : softwareName;
        String safeSoftwareVersion = softwareVersion == null || softwareVersion.isBlank() ? "Unknown version" : softwareVersion;

        return """
                IMPORTANT: You have scanned a high-risk software. Here is the report:

                Software: %s
                Version: %s
                Total Vulnerabilities: %d
                High Severity: %d
                Medium Severity: %d
                Low Severity: %d
                Overall Risk Level: %s

                Intro:
                %s

                Notable Issues:
                %s

                Risk Impact:
                %s

                Recommendations:
                %s

                Executive Summary:
                %s
                """.formatted(
                safeSoftwareName,
                safeSoftwareVersion,
                report.getTotalVulnerabilities(),
                report.getHighSeverity(),
                report.getMediumSeverity(),
                report.getLowSeverity(),
                report.getOverallRiskLevel(),
                safeText(report.getIntro()),
                formatList(report.getNotableIssues()),
                formatList(report.getRiskImpact()),
                formatList(report.getRecommendations()),
                safeText(report.getExecutiveSummary())
        );
    }

    // for formatting a list of report bullets so that they read clearly inside the plain text email
    private String formatList(List<String> items) {
        if (items == null || items.isEmpty()) {
            return "- None";
        }
        return items.stream()
                .map(this::safeText)
                .map(item -> "- " + item)
                .reduce((left, right) -> left + "\n" + right)
                .orElse("- None");
    }

    // this replaces missing or blank text with a fallback so that the email still reads properly
    private String safeText(String value) {
        return value == null || value.isBlank() ? "Not available" : value;
    }
}
