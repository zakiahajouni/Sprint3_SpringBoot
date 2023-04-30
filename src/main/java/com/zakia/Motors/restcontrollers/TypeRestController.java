package com.zakia.Motors.restcontrollers;

import com.zakia.Motors.entities.Type;
import com.zakia.Motors.service.TypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/typ")
@CrossOrigin

public class TypeRestController {
    @Autowired
    TypeService typeService;
    @RequestMapping(method = RequestMethod.GET)
    public List<Type> getAllTypes() {
        return typeService.getAllTypes();
    }

    @RequestMapping(value="/{id}",method = RequestMethod.GET)
    public Type getTypeById(@PathVariable("id") Long id) {
        return typeService.getType(id);
    }
    @RequestMapping(method = RequestMethod.POST)
    public Type saveType(@RequestBody Type type) {
        return typeService.saveType(type);
    }
   @RequestMapping(method = RequestMethod.PUT)
    public Type updateType(@RequestBody Type type) {
        return typeService.updateType(type);
    }
    @RequestMapping(value="/{id}",method = RequestMethod.DELETE)
    public void deleteType(@PathVariable("id") Long id) {
        typeService.deleteTypeById(id);
    }


}
