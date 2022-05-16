package am.ysu.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
public class IdentityProviderServer {

	public static void main(String[] args) {
//		System.setProperty("spring.config.name", "authentication");
		System.setProperty("spring.application.name", "identity_provider");
		SpringApplication.run(IdentityProviderServer.class, args);
	}

}
