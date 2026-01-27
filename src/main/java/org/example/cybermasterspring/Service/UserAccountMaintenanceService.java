package org.example.cybermasterspring.service;

import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.UserRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class UserAccountMaintenanceService {

    private final UserRepository userRepository;

    public UserAccountMaintenanceService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Scheduled(cron = "0 0 2 * * *")
    public void disableInactiveUsers() {
        LocalDateTime cutoff = LocalDateTime.now().minusMonths(1);
        List<User> inactive = userRepository.findByLastLoginAtBefore(cutoff);
        for (User user : inactive) {
            if (user.isEnabled()) {
                user.setEnabled(false);
                userRepository.save(user);
            }
        }
    }
}
