package space.titcsl.a.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import space.titcsl.a.dto.UpdateUserDto;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.UserExistsException;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.AuthenticationService;
import space.titcsl.a.service.JwtService;
import space.titcsl.a.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AccountController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    private final UserService userService;

    @GetMapping("/account/me")
    private ResponseEntity getAccountData(@RequestHeader("Authorization") String authorizationHeader) {
        // Extract the JWT token from the Authorization header
        String jwtToken = authorizationHeader.replace("Bearer ", "");

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
    }
    @PatchMapping("/update")
    public ResponseEntity<?> updateUser(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody UpdateUserDto updateUserRequest
    ) {
        try {
            String token = extractToken(authorizationHeader);
            User updatedUser = authenticationService.updateUser(updateUserRequest, token);
            return ResponseEntity.ok(updatedUser);
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }
    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Extracting the token after "Bearer "
        }
        return null;
    }


    @PostMapping("/entry/updateEmailReq")
    public ResponseEntity<?> EmailUpdateRequest(@RequestBody Map<String, String> requestBody){
        String OldEmail = requestBody.get("oldEmail");
        String NewEmail = requestBody.get("NewEmail");

        try {
            userService.updateEmailReq(OldEmail, NewEmail);
            return ResponseEntity.ok("Otp is succesfully sent on New Email And Old Email kindly verify it. Thank you!");
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }

    @PostMapping("/entry/updateEmailFinal")
    public ResponseEntity<?> updateFinalEmail(@RequestBody Map<String, String> requestBody){
        String OldEmail = requestBody.get("oldEmail");
        String NewEmail = requestBody.get("NewEmail");
        String OldOtp = requestBody.get("oldOtp");
        String NewOtp = requestBody.get("NewOtp");

        try {
            userService.updateEmailConfirm(NewEmail, NewOtp, OldEmail, OldOtp);
            return ResponseEntity.ok("You email Updated successfully");
        }catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }
}

