package com.zakia.Motors;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.repos.MotorRepository;
import com.zakia.Motors.service.MotorService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;

import java.util.Date;
import java.util.List;

@SpringBootTest
class MotorsApplicationTests {
	@Autowired
	private MotorRepository motorRepository;
	@Autowired
	private MotorService motorService;

//	@Test
	//public void testCreateMotor() {
	//	Motor prod = new Motor("kawasaki z1000", 300, 10000, new Date());
		//motorRepository.save(prod);
	//}
	@Test
	public void testFindMotor()
	{
		Motor m = motorRepository.findById(1L).get();
		System.out.println(m);
	}
	@Test
	public void testUpdateMotor()
	{
		Motor m = motorRepository.findById(1L).get();
		m.setMaxSpeedMotor(350);
		motorRepository.save(m);
	}
	@Test
	public void testDeleteMotor()
	{
		motorRepository.deleteById(1L);;
	}

	@Test
	public void testListerTousMotors()
	{
		List<Motor> motos = motorRepository.findAll();
		for (Motor m : motos)
		{
			System.out.println(m);
		}
	}

	@Test
	public void testFindByNameMotorContains()
	{
		Page<Motor> motos = motorService.getAllMotorsParPage(0,2);
		System.out.println(motos.getSize());
		System.out.println(motos.getTotalElements());
		System.out.println(motos.getTotalPages());
		motos.getContent().forEach(p -> {System.out.println(p.toString());
		});}
	@Test
	public void testFindByNomMotor()
	{
		List<Motor> moto =motorRepository.findByNameMotor("kawasaki z1000");
		for (Motor m : moto)
		{
			System.out.println(m);
		}
	}
	@Test
	public void testFindByNomMotorContains ()
	{
		List<Motor> moto=motorRepository.findByNameMotorContains("iphone X");
		for (Motor m : moto)
		{
			System.out.println(m);
		} }


















}
