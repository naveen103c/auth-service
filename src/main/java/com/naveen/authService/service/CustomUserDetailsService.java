package com.naveen.authService.service;

import com.naveen.authService.UserRepository;
import com.naveen.authService.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch the user from the database
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        //get all roles granted to user
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));
        // Convert the User entity to UserDetails (used by Spring Security)
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                simpleGrantedAuthorities);
    }
}
