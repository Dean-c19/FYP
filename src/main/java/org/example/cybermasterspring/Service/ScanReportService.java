package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.ScanReport;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ScanReportService {

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

        for (CveFinding finding : findings) {
            Double cvss = finding.getCvss();
            if (cvss == null) {
                continue;
            }
            if (cvss >= 7.0) {
                highSeverity++;
            } else if (cvss >= 4.0) {
                mediumSeverity++;
            } else {
                lowSeverity++;
            }
        }

        return new ScanReport(
                title,
                intro,
                findings.size(),
                highSeverity,
                mediumSeverity,
                lowSeverity,
                "Unknown",
                List.of(),
                List.of(),
                List.of(),
                ""
        );
    }
}
