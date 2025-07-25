package space.titcsl.arunaushadhalay.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import space.titcsl.arunaushadhalay.dto.UpdateUserDto;
import space.titcsl.arunaushadhalay.entity.User;
import space.titcsl.arunaushadhalay.exception.*;
import space.titcsl.arunaushadhalay.repository.UserRepository;
import space.titcsl.arunaushadhalay.service.AuthenticationService;
import space.titcsl.arunaushadhalay.service.JwtService;
import space.titcsl.arunaushadhalay.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    private final UserService userService;
    @Value("space.titcsl.arunaushadhalay.api.version")
    private String version;

    @GetMapping("/api/{version}/account/me")
    public ResponseEntity getAccountData(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        try {
            String jwtToken = extractToken(authorizationHeader);

            // Extract the username from the JWT token
            String username = jwtService.extractUsername(jwtToken);

            // Fetch the user details from the database based on the username
            User user = userRepository.findByEmail(username).orElse(null);

            if (user != null) {
                // Return the user details as ResponseEntity
                return ResponseEntity.ok(user);
            } else {
                // Handle the case where the user is not found
                return ResponseEntity.notFound().build();
            }

        } catch (InvalidTokenException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }catch (UserNotFoundException | GlobalErrorExceptionHandler ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            // Convert Map to JSON string using Jackson
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

    @PatchMapping("/api/{version}/account/update")
    public ResponseEntity<?> updateUser(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody UpdateUserDto updateUserRequest
    ) {
        try {
            String token = extractToken(authorizationHeader);
            User updatedUser = authenticationService.updateUser(updateUserRequest, token);
            return ResponseEntity.ok(updatedUser);
        }catch (UserNotFoundException | GlobalErrorExceptionHandler ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            // Convert Map to JSON string using Jackson
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse;
            try {
                jsonResponse = objectMapper.writeValueAsString(response);
            } catch (Exception e) {
                // Handle serialization exception
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal bits error! Sorry for inconvenience. report issue@arunayurved.com");
            }

            return ResponseEntity.status(HttpStatus.CONFLICT).body(jsonResponse);
        }catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }
    }

    @PostMapping("/api/{version}/account/enablesTfa")
    private ResponseEntity<?> enablesTfa(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader){
        String token = extractToken(authorizationHeader);
        String email = jwtService.extractUsername(token);
        try {
            authenticationService.tfaEnable(email);
        }catch (UserNotFoundException ex){
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
        return ResponseEntity.ok("You will be able to get one time password at the time of login to your email: " + email + " any issue contact issue@arunayurved.com");
    }


    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Extracting the token after "Bearer "
        }else {
            return "Error validating your account! please login again or restart your browser if not. report issue@arunayurved.com";
        }

    }


}

