package space.titcsl.arunaushadhalay.service;

import space.titcsl.arunaushadhalay.dto.*;
import space.titcsl.arunaushadhalay.entity.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SignInRequest signInRequest);

    void sendVerificationLater(String email);

    void verifyUser(String email, String otp);

    void forgotPassRequest(String email);

    void settingPasswordForgot(String email, String password, String otp);

    User updateUser(UpdateUserDto updateUserRequest, String token);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
