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

    // this service handles the scheduled background check for the accounts that should be disabled after inactivity a month
    public UserAccountMaintenanceService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // this runs every day at 2am and disables users whose last login is older than one month
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
