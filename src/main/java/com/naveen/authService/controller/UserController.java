package com.naveen.authService.controller;

import com.naveen.authService.model.User;
import com.naveen.authService.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.ResponseEntity;

import java.util.List;

@Controller
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users); // Return users with HTTP 200 OK
    }
}
