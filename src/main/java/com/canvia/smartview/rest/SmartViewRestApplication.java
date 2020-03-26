package com.canvia.smartview.rest;

import com.canvia.smartview.core.config.SmartViewCoreConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication(scanBasePackages = "com.canvia.smartview.rest")
@Import(SmartViewCoreConfig.class)
public class SmartViewRestApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(SmartViewRestApplication.class, args);
	}

}
