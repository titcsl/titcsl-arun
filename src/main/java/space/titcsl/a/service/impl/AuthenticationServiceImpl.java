package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import space.titcsl.a.dto.*;
import space.titcsl.a.entity.Role;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.GlobalErrorExceptionHandler;
import space.titcsl.a.exception.InvalidCredentialsException;
import space.titcsl.a.exception.UserExistsException;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.AuthenticationService;
import space.titcsl.a.service.EmailService;
import space.titcsl.a.service.JwtService;

import javax.swing.text.html.Option;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Logger;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${space.titcsl.a.email.support}")
    private String SupportEmail;

    public User signup(SignUpRequest signUpRequest) {
        // Check if a user with the same display name exists
        if (userRepository.existsByDisplayName(signUpRequest.getDisplayName())) {
            throw new UserExistsException("Display name already exists! Try using another cool display name for you else. contact: " + SupportEmail);
        }

        // Check if a user with the same email exists
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserExistsException("Email already exists! login with email or try resetting password else. contact: " + SupportEmail);
        }

        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setDisplayName(signUpRequest.getDisplayName());
        String otp = UUID.randomUUID().toString().substring(0, 6);
        user.setVerified(false);
        user.setHandlecode1(otp);  // Set the verification code here
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setPhone(signUpRequest.getPhone());
        user.setRole(Role.ADMIN);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        // Save the new user
        userRepository.save(user);
        emailService.sendVerificationEmail(user.getEmail(), otp);


        return user;
    }

    public void verifyUser(String email, String otp) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isVerified() && otp.equals(user.getHandlecode1())) {
                user.setVerified(true);
                user.setHandlecode1("ok");
                userRepository.save(user);
                emailService.EmailAlertsToUser(user.getEmail(), "You have create your account on Arun Ayurved. now head to the website https://arunayurved.com. start your medication journey soon. Thank You!");
            } else {
                throw new GlobalErrorExceptionHandler("The Otp you have entered is wrong! So Don't Worry Try again else. contact: " + SupportEmail);
            }
        } else {
            throw new UserNotFoundException("The user is not found so please do verification via TITCSL portal else. contact: " + SupportEmail);
        }
    }

    @Override
    public User updateUser(UpdateUserDto updateUserRequest, String token) {
        // Validate the token
        String userEmail = jwtService.extractUsername(token);
        User authUser = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("You should not do this! please login again"));

        // Check if the email is being updated to an existing email
        if (!authUser.getEmail().equals(updateUserRequest.getEmail()) && userRepository.existsByEmail(updateUserRequest.getEmail())) {
            throw new UserExistsException("Email already exists! Please choose a different email.");
        }
        if (!authUser.getDisplayName().equals(updateUserRequest.getDisplayName()) && userRepository.existsByDisplayName(updateUserRequest.getDisplayName())) {
            throw new UserExistsException("Display Name Is already given to someone");
        }

        User user = userRepository.findByEmail(updateUserRequest.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + updateUserRequest.getEmail()));

        // Check if the authenticated user is updating their own profile
        if (!authUser.getEmail().equals(updateUserRequest.getEmail())) {
            throw new GlobalErrorExceptionHandler("iInvalid Request!");
        }


        // Update the user information based on the provided fields
        if (updateUserRequest.getFirstName() != null) {
            user.setFirstName(updateUserRequest.getFirstName());
        }

        if (updateUserRequest.getLastName() != null) {
            user.setLastName(updateUserRequest.getLastName());
        }


        if (updateUserRequest.getPassword() != null) {
            // You may want to handle password encoding here
            user.setPassword(passwordEncoder.encode(updateUserRequest.getPassword()));
        }

        if (updateUserRequest.getPhone() != null) {
            user.setPhone(updateUserRequest.getPhone());
        }

        if (updateUserRequest.getDisplayName() != null) {
            user.setDisplayName(updateUserRequest.getDisplayName());
        }

        // Save the updated user
        userRepository.save(user);

        return user;
    }

    public JwtAuthenticationResponse signin(SignInRequest signInRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(),
                    signInRequest.getPassword()));

            var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() ->
                    new UserNotFoundException("Email or Password are Wrong (Email not found in server) because of this password will be* wrong else. contact: " + SupportEmail));

            if (user.isVerified()) {
                var jwt = jwtService.generateToken(user);
                var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
                JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
                jwtAuthenticationResponse.setToken(jwt);
                jwtAuthenticationResponse.setRefreshToken(refreshToken);
                return jwtAuthenticationResponse;
            } else {
                throw new GlobalErrorExceptionHandler("Verify your account if you could not verify it check the email for instruction email could be in spam/junk. But Trust us. We are since 1937 Serving peoples 14 hours a day.");
            }
        } catch (AuthenticationException ex) {
            throw new InvalidCredentialsException("Email or Password are Wrong. Try resetting it or check email or password one more time else. contact: " + SupportEmail);
        }
    }



    public void forgotPassRequest(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        String otp = UUID.randomUUID().toString().substring(0, 6);


        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (user.isVerified()) {
                user.setHandlecode2(otp);
                userRepository.save(user);
                emailService.sendVerificationEmail(email, otp);
            } else {
                throw new GlobalErrorExceptionHandler( "User not found! Try rechecking email or contact contact: " + SupportEmail);
            }
        } else {
            throw new UserNotFoundException("User not found with email! please recheck it or else. contact: " + SupportEmail);
        }

    }

    public void sendVerificationLater(String email){
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            String otp = UUID.randomUUID().toString().substring(0, 6);

            user.setHandlecode1(otp);
            userRepository.save(user);
            emailService.sendVerificationEmail(email, otp);

        } else {
            throw new UserNotFoundException("User not found with email! please recheck it or else. contact: " + SupportEmail);
        }
    }

    public void settingPasswordForgot(String email, String password, String otp){
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (otp.equals(user.getHandlecode2())) {
                user.setPassword(passwordEncoder.encode(password));
                user.setHandlecode2("ok");
                userRepository.save(user);

            } else {
                throw new GlobalErrorExceptionHandler("Invalid One-time-password. try checking it one more time.");
            }
        } else {
            throw new UserNotFoundException("User not found with email! please recheck it or else. contact: " + SupportEmail);
        }

    }


    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest){
        String userEmail =  jwtService.extractUsername(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();

            if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
                var jwt = jwtService.generateToken(user);
                JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
                jwtAuthenticationResponse.setToken(jwt);
                jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
                return jwtAuthenticationResponse;
            } else {
                throw  new GlobalErrorExceptionHandler("Please login one more time. for securing your account more than others.");
            }
    }

}
