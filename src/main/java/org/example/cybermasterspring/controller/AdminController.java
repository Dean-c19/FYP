package org.example.cybermasterspring.controller;

import org.example.cybermasterspring.dto.AdminUserDto;
import org.example.cybermasterspring.dto.ScanHistoryItem;
import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.UserRepository;
import org.example.cybermasterspring.service.VulnerabilityScanService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class AdminController {

    private final UserRepository userRepository;
    private final VulnerabilityScanService vulnerabilityScanService;

    public AdminController(UserRepository userRepository,
                           VulnerabilityScanService vulnerabilityScanService) {
        this.userRepository = userRepository;
        this.vulnerabilityScanService = vulnerabilityScanService;
    }

    @GetMapping("/api/admin/users")
    @ResponseBody
    public List<AdminUserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::toDto)
                .toList();
    }

    @PatchMapping("/api/admin/users/{id}/enabled")
    @ResponseBody
    public AdminUserDto setUserEnabled(@PathVariable Long id, @RequestBody Map<String, Boolean> body) {
        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        User user = userRepository.findById(id).orElseThrow();
        user.setEnabled(enabled);
        userRepository.save(user);
        return toDto(user);
    }

    @GetMapping("/api/admin/scans/history")
    @ResponseBody
    public List<ScanHistoryItem> getAllScanHistory() {
        return vulnerabilityScanService.getAllScanHistory();
    }

    private AdminUserDto toDto(User user) {
        return new AdminUserDto(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole(),
                user.isEnabled(),
                user.getLastLoginAt()
        );
    }
}
