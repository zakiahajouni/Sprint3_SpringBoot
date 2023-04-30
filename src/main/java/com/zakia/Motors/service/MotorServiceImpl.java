package com.zakia.Motors.service;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.entities.Type;
import com.zakia.Motors.repos.MotorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class MotorServiceImpl implements MotorService {
@Autowired
 MotorRepository motorRepository;
    @Override
    public Motor saveMotor(Motor m) {
        return motorRepository.save(m);
    }

    @Override
    public Motor updateMotor(Motor m) {
        return motorRepository.save(m);
    }

    @Override
    public void deleteMotor(Motor m) {
          motorRepository.delete(m);
    }

    @Override
    public void deleteMotorById(Long id) {
motorRepository.deleteById(id);
    }

    @Override
    public Motor getMotor(Long id) {
        return motorRepository.findById(id).get();
    }

    @Override
    public List<Motor> getAllMotors() {
        return motorRepository.findAll();
    }

    @Override
    public Page<Motor> getAllMotorsParPage(int page, int size) {
        return motorRepository.findAll(PageRequest.of(page, size));

    }

    @Override
    public List<Motor> findByNomMotor(String nom) {
        return motorRepository.findByNameMotor(nom);
    }

    @Override
    public List<Motor> findByNomMotorContains(String nom) {
        return motorRepository.findByNameMotorContains(nom);
    }

    @Override
    public List<Motor> findByNomPrix(String nom, Double prix) {
        return motorRepository.findByNomPrix(nom, prix);
    }

    @Override
    public List<Motor> findByType(Type type) {
        return motorRepository.findByType(type);
    }

    @Override
    public List<Motor> findByTypeId(Long id) {
        return motorRepository.findByTypeId(id);
    }

    @Override
    public List<Motor> findByOrderByNomMotorAsc() {
        return motorRepository.findByOrderByNameMotorAsc();
    }

    @Override
    public List<Motor> trierMotorsNomsPrix() {
        return motorRepository.trierMotorsNomsPrix();
    }


}
