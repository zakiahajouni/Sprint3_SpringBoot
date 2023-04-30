package com.zakia.Motors.restcontrollers;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.service.MotorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin

public class MotorRESTController {
    @Autowired
    MotorService motorService;
    @RequestMapping(method = RequestMethod.GET)
    public List<Motor> getAllMotors() {
        return motorService.getAllMotors();
    }
    @RequestMapping(value="/{id}",method = RequestMethod.GET)
    public Motor getMotorById(@PathVariable("id") Long id) {
        return motorService.getMotor(id);
    }
    @RequestMapping(method = RequestMethod.POST)
    public Motor createMotor(@RequestBody Motor motor) {
        return motorService.saveMotor(motor);
    }
    @RequestMapping(method = RequestMethod.PUT)
    public Motor updateMotor(@RequestBody Motor motor) {
        return motorService.updateMotor(motor);
    }
    @RequestMapping(value="/{id}",method = RequestMethod.DELETE)
    public void deleteMotor(@PathVariable("id") Long id)
    {
        motorService.deleteMotorById(id);
    }
    @RequestMapping(value="mototyp/{id}",method = RequestMethod.GET)
    public List<Motor> getMotorsByTypId(@PathVariable("id") Long id) {
        return motorService.findByTypeId(id);
    }

}
