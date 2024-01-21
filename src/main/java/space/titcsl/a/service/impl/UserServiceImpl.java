package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import space.titcsl.a.entity.Role;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.UserExistsException;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.EmailService;
import space.titcsl.a.service.UserService;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    @Value("${space.titcsl.a.email.support}")
    private String SupportEmail;

    public User updateManagementRole(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Account with email not found email: " + email));

        user.setRole(Role.MANAGEMENT);


        userRepository.save(user);
        return (user);
    }

    public ResponseEntity<?> updateEmailReq(String Oldemail, String NewEmail){


        // Check if a user with the same email exists
        if (userRepository.existsByEmail(NewEmail)){
            throw new UserExistsException("Email already exists! login with email or try resetting password else. contact: " + SupportEmail);
        }
        User user = userRepository.findByEmail(Oldemail)
                .orElseThrow(() -> new UserNotFoundException("Account not found"));
        String otp = UUID.randomUUID().toString().substring(0, 6);
        String Newotp = UUID.randomUUID().toString().substring(0, 6);

        user.setHandlecode1(otp);
        user.setHandlecode2(Newotp);
        userRepository.save(user);
        emailService.sendVerificationEmail(Oldemail, otp);
        emailService.sendVerificationEmail(NewEmail, Newotp);

        return ResponseEntity.status(HttpStatus.OK).body("Otp is successfully sent on New Email And Old Email kindly verify it. Thank you!");
    }

    public void updateEmailConfirm(String NewEmail, String otp, String OldEmail, String oldOtp){
        Optional<User> optionalUser = userRepository.findByEmail(OldEmail);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (otp.equals(user.getHandlecode2()) && oldOtp.equals(user.getHandlecode1())) {
                user.setEmail(NewEmail);
                userRepository.save(user);
            } else {
                throw new UserNotFoundException("Invalid Otp try contacting " + SupportEmail);
            }
        } else {
            throw new UserNotFoundException("User not found with email if an server error. contact: " + SupportEmail);
        }
    }

    public void DeleteUser(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            String id = user.getId();
            userRepository.deleteById(id);
        }
    }


    public void sendEmailToAllUsers(String subject, String body) {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            emailService.sendEmail(user.getEmail(), subject, body);
        }
    }

    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                return userRepository.findByEmail(username)
                        .orElseThrow(() -> new UserNotFoundException("User with that email is not found or does not belong to you. Try checking the registered phone for verifying email correctly."));
            }
        };
    }
}
