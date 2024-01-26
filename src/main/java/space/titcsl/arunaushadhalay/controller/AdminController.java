package space.titcsl.arunaushadhalay.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import space.titcsl.arunaushadhalay.entity.User;
import space.titcsl.arunaushadhalay.exception.GlobalErrorExceptionHandler;
import space.titcsl.arunaushadhalay.exception.UserNotFoundException;
import space.titcsl.arunaushadhalay.service.AuthenticationService;
import space.titcsl.arunaushadhalay.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AdminController {


    private final UserService userService;
    private final AuthenticationService authenticationService;

    @Value("space.titcsl.arunaushadhalay.api.version")
    private String version;


    @PutMapping("/api/{version}/admin/setRoleManager")
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
        } catch (UserNotFoundException | GlobalErrorExceptionHandler ex) {
            Map<String, String> response = new HashMap<>();
            response.put("message", ex.getMessage());

            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse;
            try {
                jsonResponse = objectMapper.writeValueAsString(response);
            } catch (Exception e) {
                // Handle serialization exception
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal bits error! Sorry for inconvenience. report {ReportEmail}");
            }

            return ResponseEntity.status(HttpStatus.CONFLICT).body(jsonResponse);
        }
    }

    @PostMapping("/api/{version}/admin/sendToAll")
    public String sendEmailToAllUsers(@RequestBody Map<String, String> requestBody) {
        String subject = requestBody.get("subject");
        String body = requestBody.get("body");

        userService.sendEmailToAllUsers(subject, body);
        return "Emails sent to all users successfully!";
    }

    @DeleteMapping("/api/{version}/admin/deleteUser")
    public ResponseEntity<?> deleteUser(@RequestBody Map<String, String> requestBody) {
        // Your existing method implementation
        String email = requestBody.get("email");
        userService.DeleteUser(email);

        return ResponseEntity.ok("Deleted Succesfully!");

    }


}