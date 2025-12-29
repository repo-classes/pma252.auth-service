package store.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import store.account.AccountController;
import store.account.AccountIn;
import store.account.AccountOut;

@Service
public class AuthService {

    public static final String AUTH_COOKIE_TOKEN = "__store_jwt_token";

    private Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Value("${store.token.duration}")
    private Long tokenDuration;

    @Value("${store.token.https}")
    private Boolean tokenHTTPS;

    @Autowired
    private AccountController accountController;

    @Autowired
    private JwtService jwtService;

    public String register(String name, String email, String password) {

        logger.debug(
            String.format(
                "registrando uma conta: [%s] for [%s]",
                name, email
            )
        );

        // Salvar no servico de Account
        AccountOut account = accountController.create(AccountIn.builder()
            .name(name)
            .email(email)
            .password(password)
            .build()
        ).getBody();

        // Gera um token
        String jwtString = jwtService.generate(account, tokenDuration);

        // Retorna o token
        return jwtString;
    }

    public String login(String email, String password) {

        logger.debug(String.format("required login for %s:%s", email, password));

        // Verify credentials
        ResponseEntity<AccountOut> response = accountController.findByEmailAndPassword(
            AccountIn.builder()
                .email(email)
                .password(password)
                .build()
        );
        if (!response.hasBody()) {
            logger.debug(String.format("user not found"));
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        AccountOut account = response.getBody();
        logger.debug(String.format("found user", account));

        // generate token
        return jwtService.generate(account, tokenDuration);
    }

    public AccountOut solve(String jwt) {
        return AccountOut.builder()
            .id(jwtService.getId(jwt))
            .build();
    }

    public Long getTokenDuration() {
        return tokenDuration;
    }

    public Boolean getTokenHTTPS() {
        return tokenHTTPS;
    }

}
