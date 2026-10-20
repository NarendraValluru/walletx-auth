package com.example.walletxbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import com.example.backendutil.auth.AuthUserEntity;

@SpringBootApplication
@EntityScan(basePackageClasses = AuthUserEntity.class)
public class WalletxBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(WalletxBackendApplication.class, args);
	}

}
