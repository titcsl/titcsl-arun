package space.titcsl.arunaushadhalay.service;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import space.titcsl.arunaushadhalay.entity.User;

public interface UserService {
    UserDetailsService userDetailsService();

    ResponseEntity<?> updateEmailReq(String Oldemail, String NewEmail);

    void updateEmailConfirm(String NewEmail, String otp, String OldEmail, String oldOtp);

    User updateManagementRole(String email);

    void sendEmailToAllUsers(String subject, String body);

    void DeleteUser(String email);

}
