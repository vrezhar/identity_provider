package am.ysu.identity.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

@Component("passwordEncoder")
public class LegacyAwarePasswordEncoder implements PasswordEncoder {
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    private final List<MessageDigestPasswordEncoder> messageDigestPasswordEncoders = List.of(
            new MessageDigestPasswordEncoder("SHA-256"),
            new MessageDigestPasswordEncoder("MD5"),
            new MessageDigestPasswordEncoder("SHA-384"),
            new MessageDigestPasswordEncoder("SHA-512"),
            new MessageDigestPasswordEncoder("SHA1")
    );
    private final ThreadLocal<Boolean> oldAlgorithmMatch = new ThreadLocal<>();

    public boolean isOldAlgorithmMatch() {
        return Objects.requireNonNullElse(oldAlgorithmMatch.get(), false);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return bCryptPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if(messageDigestPasswordEncoders.stream().anyMatch(encoder -> encoder.matches(rawPassword, encodedPassword))) {
            oldAlgorithmMatch.set(true);
            return true;
        }
        return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
    }
}
