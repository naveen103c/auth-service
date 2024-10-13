package com.naveen.authService.controller;

import com.naveen.authService.model.JwtRequest;
import com.naveen.authService.model.JwtResponse;
import com.naveen.authService.model.User;
import com.naveen.authService.service.UserService;
import com.naveen.authService.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtUtil jwtUtil;
    @PostMapping("/login")
    public JwtResponse authenticateUser(@RequestBody JwtRequest loginRequest) {

        User user = userService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());

//        String encodedPassword = passwordEncoder.encode(loginRequest.getPassword());
//        loginRequest.setPassword(encodedPassword);

        // 1. Authenticate the user using the provided username and password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // 2. Set the authentication in the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Generate the JWT token
        String jwt = jwtUtil.generateToken(authentication);

        // 4. Return the token wrapped in a JwtResponse object
        return new JwtResponse(jwt);
    }

    @PostMapping("/register")
    public void registerUser(@RequestBody User user) {
      userService.registerUser(user);
    }

}
