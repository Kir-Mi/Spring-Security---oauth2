package com.example.SpringSecurityoauth2.service;

import com.example.SpringSecurityoauth2.model.User;
import com.example.SpringSecurityoauth2.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
public class UserService {
    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void save(User user) {
        log.info("User " + user.getUsername() + " with role: " + user.getRole() + " was created");
        userRepository.save(user);
    }
}