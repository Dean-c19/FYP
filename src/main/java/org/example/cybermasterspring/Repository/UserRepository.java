package org.example.cybermasterspring.repository;

import org.example.cybermasterspring.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.time.LocalDateTime;
import java.util.List;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    List<User> findByLastLoginAtBefore(LocalDateTime cutoff);
}
