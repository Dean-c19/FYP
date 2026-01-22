package org.example.cybermasterspring.dto;

import java.time.LocalDateTime;

public class AdminUserDto {
    private final Long id;
    private final String username;
    private final String email;
    private final String role;
    private final boolean enabled;
    private final LocalDateTime lastLoginAt;

    public AdminUserDto(Long id, String username, String email, String role, boolean enabled, LocalDateTime lastLoginAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.enabled = enabled;
        this.lastLoginAt = lastLoginAt;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getRole() { return role; }
    public boolean isEnabled() { return enabled; }
    public LocalDateTime getLastLoginAt() { return lastLoginAt; }
}
