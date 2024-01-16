package space.titcsl.a.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import space.titcsl.a.entity.User;

public interface UserService {
    UserDetailsService userDetailsService();
    User updateManagementRole(String email);
}
