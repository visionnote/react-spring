package react.reply.security;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.stream.IntStream;

@SpringBootTest
@Log4j2
public class JwtTest {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ApiUserRepository apiUserRepository;

    @Test
    public void testInserts() {
        ApiUser apiUser = ApiUser.builder()
                .client_id("client_id")
                .client_secret(passwordEncoder.encode("client_secret"))
                .build();
        apiUserRepository.save(apiUser);
    }

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate() {
        Map<String, Object> claimMap = Map.of("client_id", "client_id");
        log.info(claimMap);
        String jwtStr = jwtUtil.generationToken(claimMap, 1);
        log.info(jwtStr);
    }

    @Test
    public void testValidate() throws Exception{

        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnRfaWQiLCJpYXQiOjE3NDAyMzcwODksImV4cCI6MTc0MDMyMzQ4OX0.NOOudgvwIwMe4RdIj9XUYHwgo3HskIioptk7btCoZ2A";
        Map<String, Object> value = jwtUtil.validateToken(jwtStr);
        System.out.println(value);
    }
}
