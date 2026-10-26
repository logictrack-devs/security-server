package security_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security_service.model.Usuario;
import java.util.Optional;
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByUsername(String username);
    boolean existsByUsernameOrEmail(String username, String email);
}

