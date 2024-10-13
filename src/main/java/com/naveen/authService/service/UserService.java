package com.naveen.authService.service;

import com.naveen.authService.UserRepository;
import com.naveen.authService.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Random;

@Service
public class UserService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    // Method to authenticate user
    public User authenticateUser(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Validate the password using the stored encoded password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        return user; // Authentication successful
    }

    public void registerUser(User user) {
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword); // Set the encoded password
        userRepository.save(user); // Save the user to the database
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
