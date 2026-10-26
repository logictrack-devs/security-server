package security_service.config;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import security_service.model.Usuario;
import security_service.repository.UsuarioRepository;
import java.util.List;
import java.util.Map;
@RestController
@RequestMapping("/api")
public class UsuarioController {
    private final UsuarioRepository repo;
    public UsuarioController(UsuarioRepository r) { repo = r; }
    @GetMapping("/usuarios/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        var u = repo.findByUsername(jwt.getSubject()).orElseThrow();
        return Map.of("id", u.getId(), "username", u.getUsername(),
                "email", u.getEmail(), "rol", u.getRol());
    }
    @GetMapping("/admin/usuarios")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Usuario> listar() { return repo.findAll();
    }

}

