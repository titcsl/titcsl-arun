package space.titcsl.a.service;

import space.titcsl.a.dto.*;
import space.titcsl.a.entity.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SignInRequest signInRequest);

    User updateUser(UpdateUserDto updateUserRequest, String token);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
