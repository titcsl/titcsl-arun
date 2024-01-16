package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import space.titcsl.a.entity.Role;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.UserNotFoundException;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.JwtService;
import space.titcsl.a.service.UserService;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    public User updateManagementRole(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Account with email not found email: " + email));

        user.setRole(Role.MANAGEMENT);

        userRepository.save(user);
        return (user);
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
