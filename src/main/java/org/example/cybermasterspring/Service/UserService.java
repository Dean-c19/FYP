package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.model.User;

public interface UserService {
    User registerNewUser(UserRegistrationDto registrationDto);
}
