package security_service.service;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import security_service.model.*;
import security_service.repository.UsuarioRepository;
@Service
public class UsuarioService {
    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;
    public UsuarioService(UsuarioRepository r, PasswordEncoder e) {
        repo = r; encoder = e;
    }
    public Usuario registrar(String username, String email, String rawPassword, Rol rol) {
        if (repo.existsByUsernameOrEmail(username, email))
            throw new IllegalArgumentException("Usuario o email ya registrado");
        var u = new Usuario();
        u.setUsername(username);
        u.setEmail(email);
        u.setPassword(encoder.encode(rawPassword)); // hash BCrypt
        u.setRol(rol == null ? Rol.CLIENTE : rol);
        return repo.save(u);
    }
}
