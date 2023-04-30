package com.zakia.Motors.service;

import com.zakia.Motors.entities.Type;
import com.zakia.Motors.repos.MotorRepository;
import com.zakia.Motors.repos.TypeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class TypeServiceImpl implements TypeService {
    @Autowired
    TypeRepository typeRepository;
    @Override
    public Type saveType(Type t) {
        return typeRepository.save(t);
    }

    @Override
    public Type updateType(Type t) {
        return typeRepository.save(t);
    }

    @Override
    public void deleteType(Type t) {
typeRepository.delete(t);
    }

    @Override
    public void deleteTypeById(Long id) {
typeRepository.deleteById(id);
    }

    @Override
    public Type getType(Long id) {
        return typeRepository.findById(id).get();
    }

    @Override
    public List<Type> getAllTypes() {
        return typeRepository.findAll();
    }

    @Override
    public Page<Type> getAllTypesParPage(int page, int size) {
        return typeRepository.findAll(PageRequest.of(page, size));
    }

}
