package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import space.titcsl.a.entity.Role;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.EmailService;
import space.titcsl.a.service.JwtService;
import space.titcsl.a.service.UserService;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final EmailService emailService;

    public User updateManagementRole(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Account with email not found email: " + email));

        user.setRole(Role.MANAGEMENT);

        userRepository.save(user);
        return (user);
    }

    public ResponseEntity<?> updateEmailReq(String Oldemail, String NewEmail){
        User user = userRepository.findByEmail(Oldemail)
                .orElseThrow(() -> new UserNotFoundException("Account not found"));
        String otp = UUID.randomUUID().toString().substring(0, 6);
        String Newotp = UUID.randomUUID().toString().substring(0, 6);

        user.setHandlecode1(otp);
        user.setHandlecode2(Newotp);
        userRepository.save(user);
        emailService.sendVerificationEmail(Oldemail, otp);
        emailService.sendVerificationEmail(NewEmail, Newotp);

        return ResponseEntity.status(HttpStatus.OK).body("Otp is succesfully sent on New Email And Old Email kindly verify it. Thank you!");
    }

    public void updateEmailConfirm(String NewEmail, String otp, String OldEmail, String oldOtp){
        Optional<User> optionalUser = userRepository.findByEmail(OldEmail);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (otp.equals(user.getHandlecode2()) && oldOtp.equals(user.getHandlecode1())) {
                user.setEmail(NewEmail);
                userRepository.save(user);
            } else {
                throw new UserNotFoundException("Invalid Otp try contacting support@arunayurved.com");
            }
        } else {
            throw new UserNotFoundException("User not found with email if an server error contact support@arunayurved.com");
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
