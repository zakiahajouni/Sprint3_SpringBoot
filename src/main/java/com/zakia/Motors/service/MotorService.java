package com.zakia.Motors.service;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.entities.Type;
import org.springframework.data.domain.Page;

import java.util.List;

public interface MotorService {
   Motor saveMotor(Motor m);
    Motor updateMotor(Motor m);
    void deleteMotor(Motor m);
    void deleteMotorById(Long id);
    Motor getMotor(Long id);
    List<Motor> getAllMotors();
    Page<Motor> getAllMotorsParPage(int page, int size);

 List<Motor> findByNomMotor(String nom);
 List<Motor> findByNomMotorContains(String nom);
 List<Motor> findByNomPrix (String nom, Double prix);
 List<Motor> findByType (Type type);
 List<Motor> findByTypeId(Long id);
 List<Motor> findByOrderByNomMotorAsc();
 List<Motor> trierMotorsNomsPrix();


}
