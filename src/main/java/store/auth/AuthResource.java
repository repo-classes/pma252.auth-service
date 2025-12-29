package store.auth;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import store.account.AccountOut;

@RestController
public class AuthResource implements AuthController {

    @Autowired
    private AuthService authService;

    @Override
    public ResponseEntity<Void> register(RegisterIn in, String origin) {
        final String jwt = authService.register(
            in.name(), in.email(), in.password()
        );
        return responseToken(jwt, origin);
    }

    @Override
    public ResponseEntity<Void> login(LoginIn in, String origin) {
        final String jwt = authService.login(
            in.email(),
            in.password()
        );
        return responseToken(jwt, origin);
    }

    @Override
    public ResponseEntity<Void> logout(String origin) {
        return responseToken("", origin);
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

    private ResponseEntity<Void> responseToken(String jwt, String origin) {
        return ResponseEntity
            .created(
                ServletUriComponentsBuilder.fromCurrentRequest().build().toUri()
            )
            .header(HttpHeaders.SET_COOKIE,
                ResponseCookie.from(AuthService.AUTH_COOKIE_TOKEN, jwt)
                    .httpOnly(true)
                    .sameSite("None")
                    .secure(authService.getTokenHTTPS()) // true em HTTPS
                    .path("/")
                    .maxAge(Duration.ofMillis(authService.getTokenDuration()))
                    .build()
                .toString()
            )
            .header("Access-Control-Allow-Origin", origin)
            .header("Access-Control-Allow-Credentials", "true")
            .build();
    }

}
