package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.ScanReport;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailAlertService {

    private final JavaMailSender mailSender;

    public EmailAlertService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendHighRiskScanAlert(String recipientEmail,
                                      String softwareName,
                                      String softwareVersion,
                                      ScanReport report) {
    }
}
