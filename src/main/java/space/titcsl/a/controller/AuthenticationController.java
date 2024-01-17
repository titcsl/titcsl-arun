package space.titcsl.a.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.*;
import space.titcsl.a.dto.*;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.InvalidCredentialsException;
import space.titcsl.a.exception.UserExistsException;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.AuthenticationService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignUpRequest signUpRequest) {
        try {
            User user = authenticationService.signup(signUpRequest);
            return ResponseEntity.ok(user);
        } catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody SignInRequest signInRequest) {
        try {
            return ResponseEntity.ok(authenticationService.signin(signInRequest));
        } catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        } catch (InvalidCredentialsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }
    }
    @PostMapping("/refresh/token")
    public ResponseEntity<JwtAuthenticationResponse> refreshAndGetToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/verificationLaterGen")
    public ResponseEntity<String> verifyLaterEmail(@RequestBody Map<String, String> requestBody) {
        try {
            String email = requestBody.get("email");
            authenticationService.sendVerificationLater(email);



            return ResponseEntity.ok("Otp Sent successful");
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            // Convert Map to JSON string using Jackson
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse;
            try {
                jsonResponse = objectMapper.writeValueAsString(response);
            } catch (Exception e) {
                // Handle serialization exception
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error converting to JSON");
            }

            return ResponseEntity.status(HttpStatus.CONFLICT).body(jsonResponse);
        }
    }


    @PostMapping("/verify")
    public ResponseEntity<String> verify(@RequestBody VerificationRequest verificationRequest) {
        try {
            String email = verificationRequest.getEmail();
            String otp = verificationRequest.getOtp();
            authenticationService.verifyUser(email, otp);

            // Verification successful
            return ResponseEntity.ok("Verification successful");
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            // Convert Map to JSON string using Jackson
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse;
            try {
                jsonResponse = objectMapper.writeValueAsString(response);
            } catch (Exception e) {
                // Handle serialization exception
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error converting to JSON");
            }

            return ResponseEntity.status(HttpStatus.CONFLICT).body(jsonResponse);
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> ForgotPasswordRequest(@RequestBody Map<String, String> requestBody){
        String email = requestBody.get("email");
        try {
            authenticationService.forgotPassRequest(email);
            return ResponseEntity.ok().body("Otp Sent Succesfully");
        } catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

    }

    @PostMapping("/verify-forgot-password")
    public ResponseEntity<?> ForgotPasswordValidiate(@RequestBody Map<String, String> requestBody){
        String email = requestBody.get("email");
        String otp = requestBody.get("otp");
        String password = requestBody.get("password");

        try {
            authenticationService.settingPasswordForgot(email, password, otp);
            return ResponseEntity.ok().body("Password Setted Succesfully.");
        } catch (UserExistsException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } catch (UserNotFoundException ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

    }



}
