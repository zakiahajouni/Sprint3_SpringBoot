package com.zakia.Motors;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.service.MotorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

@SpringBootApplication
public class MotorsApplication implements CommandLineRunner {
	@Autowired
	private RepositoryRestConfiguration repositoryRestConfiguration;

	MotorService motorService;
	public static void main(String[] args) {
		SpringApplication.run(MotorsApplication.class, args);
	}
	//@Override
	//public void run(String... args) throws Exception {
		//motorService.saveMotor(new Motor();
		//motorService.saveMotor(new Motor();
		//motorService.saveMotor(new Motor();
	@Override
	public void run(String... args) throws Exception {
		repositoryRestConfiguration.exposeIdsFor(Motor.class);
	}
}
