package space.titcsl.arunaushadhalay.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import space.titcsl.arunaushadhalay.exception.UserNotFoundException;
import space.titcsl.arunaushadhalay.service.UserService;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class PublicAccountRegistrar {

    private final UserService userService;
    @Value("space.titcsl.arunaushadhalay.api.version")
    private String version;

    @PostMapping("/api/{version}/entry/updateEmailReq")
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

    @PostMapping("/api/{version}/entry/updateEmailFinal")
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
