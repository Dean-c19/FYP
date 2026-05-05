package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminRegistrationPassword;

    // service that handles the main account creation logic and also uses the configured admin registration password when needed
    public UserServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           @Value("${app.admin.registration-password:}") String adminRegistrationPassword) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminRegistrationPassword = adminRegistrationPassword;
    }

    // this creates a new user after checking duplicate details, matching passwords, and optional admin registration rules
    @Override
    @Transactional
    public User registerNewUser(UserRegistrationDto dto) {

        if (userRepository.existsByUsername(dto.getUsername())) {
            throw new RuntimeException("Username already taken");
        }

        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new RuntimeException("Email already in use");
        }

        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new RuntimeException("Passwords do not match");
        }

        boolean isAdmin = dto.isAdmin();
        // a user must provide the admin password if they are tying to register as one
        if (isAdmin) {
            if (dto.getAdminPassword() == null || dto.getAdminPassword().isBlank()) {
                throw new RuntimeException("Admin password is required");
            }
            if (!adminRegistrationPassword.equals(dto.getAdminPassword())) {
                throw new RuntimeException("Invalid admin password");
            }
        }

        User user = new User();
        user.setUsername(dto.getUsername());
        user.setEmail(dto.getEmail());
        // the password is hashed before it saves so that the db never stores plain text passwords
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setRole(isAdmin ? "ROLE_ADMIN" : "ROLE_USER");
        user.setEnabled(true);

        return userRepository.save(user);
    }
}
