package space.titcsl.arunaushadhalay.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import space.titcsl.arunaushadhalay.dto.*;
import space.titcsl.arunaushadhalay.entity.Role;
import space.titcsl.arunaushadhalay.entity.User;
import space.titcsl.arunaushadhalay.exception.GlobalErrorExceptionHandler;
import space.titcsl.arunaushadhalay.exception.InvalidCredentialsException;
import space.titcsl.arunaushadhalay.exception.UserExistsException;
import space.titcsl.arunaushadhalay.exception.UserNotFoundException;
import space.titcsl.arunaushadhalay.repository.UserRepository;
import space.titcsl.arunaushadhalay.service.AuthenticationService;
import space.titcsl.arunaushadhalay.service.EmailService;
import space.titcsl.arunaushadhalay.service.JwtService;

import java.util.HashMap;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${space.titcsl.arunaushadhalay.email.support}")
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

            if (!user.isVerified() && otp.equals(user.getHandlecode1())) {
                user.setVerified(true);
                user.setHandlecode1("ok");
                String name = user.getFirstName();
                userRepository.save(user);
                emailService.sendEmail(email, "Welcome to Arun Aushadhalay - Your Gateway to Holistic Healing!", "Dear " + name + "\n" +
                        "\n" +
                        "\n" +
                        "Namaste!  We are thrilled to extend a warm welcome to you as a valued member of Arun Aushadhalay. Congratulations on successfully registering with us!\n" +
                        "\n" +
                        "At Arun Aushadhalay, we are committed to providing you with a unique and enriching experience on your path to holistic healing. Your journey towards well-being and balance begins now, and we're honored to be a part of it.\n" +
                        "\n" +
                        "Explore our platform to discover a treasure trove of Ayurvedic remedies, wellness tips, and personalized guidance. Whether you're seeking natural solutions for specific health concerns or looking to enhance your overall vitality, our dedicated team is here to support you.\n" +
                        "\n" +
                        "Feel free to immerse yourself in the wisdom of Ayurveda, and don't hesitate to reach out if you have any questions. Your well-being is our priority, and we are here to ensure your experience with Arun Aushadhalay is both fulfilling and transformative.\n" +
                        "\n" +
                        "Thank you for entrusting us with your health journey. Here's to a life of vibrant health and harmony!\n" +
                        "\n" +
                        "Yours faithfully," +
                        "\n" +
                        "Arun Aushadhalay," +
                        "\n" +
                        "Main road Farshi," +
                        "\n" +
                        "Khamgaon-444303" +
                        "\n" +
                        "Maharashtra");
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
            throw new GlobalErrorExceptionHandler("Invalid Request!");
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

    public void tfaEnable(String email){
        User authUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Please login again! 256-exception error."));
        String name = authUser.getFirstName();
        authUser.setTfa(true);
        userRepository.save(authUser);
        emailService.sendEmail(email, "Two-Factor Authentication (2FA) Activation - Arun Aushadhalay", "Dear " + name + "\n" +
                "\n" +
                "Congratulations on successfully enabling (2FA) for your Arun Aushadhalay account! To enhance the security of your account, we strongly recommend activating Two-Factor Authentication (2FA) bu You have already enabled for it Thank You!.\n" +
                "\n" +
                "\n" +
                "\n" +
                "Yours faithfully," +
                "\n" +
                "Arun Aushadhalay," +
                "\n" +
                "Main road Farshi," +
                "\n" +
                "Khamgaon-444303" +
                "\n" +
                "Maharashtra");
    }

    public JwtAuthenticationResponse tfaVerify(String email, String otp, String ip_addr){
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Email exception change!"));
        String db_otp = user.getHandlecode1();
        if (Objects.equals(otp, db_otp)){
            var jwt = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            user.setHandlecode1(null);
            jwtAuthenticationResponse.setRefreshToken(refreshToken);
            emailService.EmailAlertsToUser(email, "Dear " + user.getFirstName() +
                    "\n" +
                    "Your Arun Aushadhalay account was just accessed from IP Address: " + ip_addr + ". If this wasn't you, act now!\n" +
                    "\n" +
                    "Reset Password to secure your account immediately. Ignoring this could jeopardize your wellness data.\n" +
                    "\n" +
                    "Stay in control with Arun Aushadhalay – act fast, reset your password, and enjoy a secure and empowering journey.\n" +
                    "\n" +
                    "\n" +
                    "Click on this link to reset your password: " + "https://arunayurved.com/ForgotPassword/Request" +
                    "\n" +
                    "\n" +
                    "Best,\n" +
                    "Security Council of TITCSL.\n" +
                    "Arun Aushadhalay" +
                    "\n" +
                    "Security Team");
            userRepository.save(user);
            return jwtAuthenticationResponse;

        } else {

            emailService.EmailAlertsToUser(email, "Dear " + user.getFirstName() +
                    "\n" +
                    "Your Arun Aushadhalay account was just accessed from IP Address: " + ip_addr + ". If this wasn't you, act now!\n" +
                    "\n" +
                    "Reset your password to secure your account immediately. Ignoring this could jeopardize your wellness data.\n" +
                    "\n" +
                    "Stay in control with Arun Aushadhalay – act fast, reset your password, and enjoy a secure and empowering journey.\n" +
                    "\n" +
                    "\n" +
                    "Click on this link to reset your password: " + "https://arunayurved.com/ForgotPassword/Request" +
                    "\n" +
                    "\n" +

                    "Best,\n" +
                    "Security Council of TITCSL.\n" +
                    "Arun Aushadhalay" +
                    "\n" +
                    "Security Team");
            throw new GlobalErrorExceptionHandler("Invalid request of login we have captured you ip address and just notify the registered email of the account holder. after 3 time the account will be locked.");
        }
    }

    public JwtAuthenticationResponse signin(SignInRequest signInRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(),
                    signInRequest.getPassword()));

            var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() ->
                    new UserNotFoundException("Email or Password are Wrong (Email not found in server) because of this password will be* wrong else. contact: " + SupportEmail));

        if (user.isTfa()) {
            String otp = UUID.randomUUID().toString().substring(0, 6);
            user.setHandlecode1(otp);
            userRepository.save(user);
            emailService.sendVerificationEmail(user.getEmail(), otp);
        }else {


            if (user.isVerified()) {
                var jwt = jwtService.generateToken(user);
                var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
                JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
                jwtAuthenticationResponse.setToken(jwt);
                jwtAuthenticationResponse.setRefreshToken(refreshToken);
                emailService.EmailAlertsToUser(signInRequest.getEmail(), "Dear " + user.getFirstName() +
                        "\n" +
                        "Your Arun Aushadhalay account was just accessed. If this wasn't you, act now!\n" +
                        "\n" +
                        "Reset your password to secure your account immediately. Ignoring this could jeopardize your wellness data.\n" +
                        "\n" +
                        "Stay in control with Arun Aushadhalay – act fast, reset your password, and enjoy a secure and empowering journey.\n" +
                        "\n" +
                        "\n" +
                        "Click on this link to reset your password: " + "https://arunayurved.com/ForgotPassword/Request" +
                        "\n" +
                        "\n" +

                        "Best,\n" +
                        "Security Council of TITCSL.\n" +
                        "Arun Aushadhalay" +
                        "\n" +
                        "Security Team");
                return jwtAuthenticationResponse;
            } else {
                throw new GlobalErrorExceptionHandler("Verify your account if you could not verify it check the email for instruction email could be in spam/junk. But Trust us. We are since 1937 Serving peoples 14 hours a day.");
            }
        }

        } catch (AuthenticationException ex) {
            throw new InvalidCredentialsException("Email or Password are Wrong. Try resetting it or check email or password one more time else. contact: " + SupportEmail);
        }
        return null;
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
                throw new GlobalErrorExceptionHandler( "User not found! Try rechecking email or contact: " + SupportEmail);
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
