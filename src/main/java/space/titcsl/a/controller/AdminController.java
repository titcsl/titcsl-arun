package space.titcsl.a.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.AuthenticationService;
import space.titcsl.a.service.JwtService;
import space.titcsl.a.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    private final UserService userService;

    @PutMapping("/setRoleManager")
    public ResponseEntity<?> updateRole(@RequestBody Map<String, String> requestBody) {
        try {
            String email = requestBody.get("email");

            if (email == null) {
                // Handle the case where the 'email' parameter is not provided in the request body
                Map<String, String> response = new HashMap<>();
                response.put("message", "Email is required in the request body.");
                return ResponseEntity.badRequest().body(response);
            }

            User updatedUser = userService.updateManagementRole(email);
            return ResponseEntity.ok(updatedUser);
        } catch (UserNotFoundException e) {
            Map<String, String> response = new HashMap<>();
            response.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }




}
