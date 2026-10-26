package security_service.service;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import security_service.repository.UsuarioRepository;
import java.util.List;
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UsuarioRepository repo;
    public UserDetailsServiceImpl(UsuarioRepository r) { repo = r; }
    @Override
    public UserDetails loadUserByUsername(String username) {
        var u = repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        return new User(u.getUsername(), u.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_" + u.getRol().name())));
    }
}

