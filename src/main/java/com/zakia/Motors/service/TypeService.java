package com.zakia.Motors.service;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.entities.Type;
import org.springframework.data.domain.Page;

import java.util.List;

public interface TypeService {
    Type saveType(Type t);
    Type updateType(Type t);
    void deleteType(Type t);
    void deleteTypeById(Long id);
    Type getType(Long id);
    List<Type> getAllTypes();
    Page<Type> getAllTypesParPage(int page, int size);


}
