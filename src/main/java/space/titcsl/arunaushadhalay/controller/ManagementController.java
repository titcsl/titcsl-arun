package space.titcsl.arunaushadhalay.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import space.titcsl.arunaushadhalay.service.UserService;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class ManagementController {

    private final UserService userService;
    @Value("space.titcsl.arunaushadhalay.api.version")
    private String version;

    @DeleteMapping("/api/{version}/management/deleteUser")
    public ResponseEntity<?> deleteUser(@RequestBody Map<String, String> requestBody, @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        // Your existing method implementation
        String email = requestBody.get("email");

        userService.DeleteUser(email);
        return ResponseEntity.ok("Deleted Successfully!");

    }
}
