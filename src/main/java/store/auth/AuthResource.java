package store.auth;

import java.time.Duration;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import store.account.AccountOut;

@RestController
public class AuthResource implements AuthController {

    private Logger logger = LoggerFactory.getLogger(AuthResource.class);

    @Autowired
    private AuthService authService;

    @Override
    public ResponseEntity<Void> register(RegisterIn in, String origin) {
        final String jwt = authService.register(
            in.name(), in.email(), in.password()
        );
        return ResponseEntity.created(
                ServletUriComponentsBuilder.fromCurrentRequest().build().toUri()
            )
            .header(HttpHeaders.SET_COOKIE, buildTokenCookie(jwt, origin, authService.getTokenDuration()).toString())
            .build();
    }

    @Override
    public ResponseEntity<Void> login(LoginIn in, String origin) {
        final String jwt = authService.login(
            in.email(),
            in.password()
        );
        ResponseEntity<Void> response = ResponseEntity
            .ok()
            .header(HttpHeaders.SET_COOKIE, buildTokenCookie(jwt, origin, authService.getTokenDuration()).toString())
            .build();
        logger.debug("Response: " + response);
        return response;
    }

    @Override
    public ResponseEntity<Void> logout(String origin) {
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, buildTokenCookie(null, origin, 0l).toString())
            .build();
    }

    @Override
    public ResponseEntity<Map<String, String>> solve(TokenOut in) {
        AccountOut account = authService.solve(in.jwt());
        return ResponseEntity.ok(
            Map.of(
                "idAccount", account.id()
            )
        );
    }

    private ResponseCookie buildTokenCookie(String content, String origin, Long duration) {
        return ResponseCookie.from(AuthService.AUTH_COOKIE_TOKEN, content)
            .httpOnly(true)
            .sameSite("None")
            .secure(authService.getTokenHTTPS()) // true em HTTPS
            .path("/")
            .maxAge(Duration.ofMillis(duration))
            .build();
        // .header("Access-Control-Allow-Origin", origin)
        // .header("Access-Control-Allow-Credentials", "true")
    }

}
