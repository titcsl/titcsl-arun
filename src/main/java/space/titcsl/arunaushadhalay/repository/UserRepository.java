package space.titcsl.arunaushadhalay.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import space.titcsl.arunaushadhalay.entity.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmail(String email);
    boolean existsByDisplayName(String displayName);

    boolean existsByEmail(String email);
}
