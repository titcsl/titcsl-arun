package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import space.titcsl.a.dto.*;
import space.titcsl.a.entity.Role;
import space.titcsl.a.entity.User;
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

    public User signup(SignUpRequest signUpRequest) {
        // Check if a user with the same display name exists
        if (userRepository.existsByDisplayName(signUpRequest.getDisplayName())) {
            throw new UserExistsException("Display name already exists! Try using another cool display name for you.");
        }

        // Check if a user with the same email exists
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserExistsException("Email already exists! login with email or try resetting password. Thank You!");
        }

        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setDisplayName(signUpRequest.getDisplayName());
        String otp = UUID.randomUUID().toString().substring(0, 6);
        user.setVerified(false);
        user.setVerificationCode(otp);  // Set the verification code here
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setPhone(signUpRequest.getPhone());
        user.setRole(Role.USER);
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

            if (!user.isVerified() && otp.equals(user.getVerificationCode())) {
                user.setVerified(true);
                userRepository.save(user);
            } else {
                throw new UserNotFoundException("Invalid OTP or User not found");
            }
        } else {
            throw new UserNotFoundException("User not found");
        }
    }
    @Override
    public User updateUser(UpdateUserDto updateUserRequest, String token) {
        // Validate the token
        String userEmail = jwtService.extractUsername(token);
        User authUser = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("Authenticated user not found"));

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
            throw new UserNotFoundException("User not authorized to update this profile");
        }



        // Update the user information based on the provided fields
        if (updateUserRequest.getFirstName() != null) {
            user.setFirstName(updateUserRequest.getFirstName());
        }

        if (updateUserRequest.getLastName() != null) {
            user.setLastName(updateUserRequest.getLastName());
        }

        if (updateUserRequest.getEmail() != null) {
            user.setEmail(updateUserRequest.getEmail());
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

            var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Email or Password are Wrong. Try resetting it or check email or password one more time"));
            var jwt = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshToken);
            return jwtAuthenticationResponse;

        } catch (IllegalArgumentException ex) {
            throw ex;
        }

    }




    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest){
        String userEmail =  jwtService.extractUsername(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        if(jwtService.isTokenValid(refreshTokenRequest.getToken(), user)){
            var jwt = jwtService.generateToken(user);
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }
        return null;
    }

}
