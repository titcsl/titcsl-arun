package space.titcsl.arunaushadhalay.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import space.titcsl.arunaushadhalay.entity.User;
import space.titcsl.arunaushadhalay.exception.GlobalErrorExceptionHandler;
import space.titcsl.arunaushadhalay.exception.UserNotFoundException;
import space.titcsl.arunaushadhalay.service.AuthenticationService;
import space.titcsl.arunaushadhalay.service.JwtService;
import space.titcsl.arunaushadhalay.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AdminController {


    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    @Value("space.titcsl.arunaushadhalay.api.version")
    private String version;


    @PutMapping("/api/{version}/admin/setRoleManager")
    public ResponseEntity<?> updateRole(@RequestBody Map<String, String> requestBody, @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        try {
            String email = requestBody.get("email");
            String token = extractToken(authorizationHeader);
            String email1 = jwtService.extractUsername(token);
            if (email == null) {
                // Handle the case where the 'email' parameter is not provided in the request body
                Map<String, String> response = new HashMap<>();
                response.put("message", "Email is required in the request body.");
                return ResponseEntity.badRequest().body(response);
            }

            User updatedUser = userService.updateManagementRole(email, email1);
            return ResponseEntity.ok(updatedUser);
        } catch (UserNotFoundException | GlobalErrorExceptionHandler ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse;
            try {
                jsonResponse = objectMapper.writeValueAsString(response);
            } catch (Exception e) {
                // Handle serialization exception
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal bits error! Sorry for inconvenience. report issue@arunayurved.com");
            }

            return ResponseEntity.status(HttpStatus.CONFLICT).body(jsonResponse);
        }
    }

    @PostMapping("/api/{version}/admin/sendToAll")
    public String sendEmailToAllUsers(@RequestBody Map<String, String> requestBody, @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        String subject = requestBody.get("subject");
        String body = requestBody.get("body");
        String token = extractToken(authorizationHeader);
        String email = jwtService.extractUsername(token);


        userService.sendEmailToAllUsers(subject, body, email);
        return "Emails sent to all users successfully!";
    }

    @DeleteMapping("/api/{version}/admin/deleteUser")
    public ResponseEntity<?> deleteUser(@RequestBody Map<String, String> requestBody, @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        // Your existing method implementation
        String email = requestBody.get("email");

        userService.DeleteUser(email);
        return ResponseEntity.ok("Deleted Succesfully!");

    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Extracting the token after "Bearer "
        }else {
            return "Error validating your account! please login again or reload your browser if not. report issue@arunayurved.com";
        }

    }


}