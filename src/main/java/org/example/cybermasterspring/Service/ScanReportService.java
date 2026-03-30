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

        return new ScanReport(
                title,
                intro,
                findings.size(),
                0,
                0,
                0,
                "Unknown",
                List.of(),
                List.of(),
                List.of(),
                ""
        );
    }
}
