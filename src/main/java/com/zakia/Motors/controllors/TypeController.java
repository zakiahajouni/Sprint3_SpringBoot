package com.zakia.Motors.controllors;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.entities.Type;
import com.zakia.Motors.service.MotorService;
import com.zakia.Motors.service.TypeService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class TypeController {
    @Autowired
    MotorService motorService;
    @Autowired
    TypeService typeService;
    @RequestMapping("/Create")
    public String showCreate(ModelMap modelMap)
    {
        modelMap.addAttribute("type", new Type());
        modelMap.addAttribute("mode", "new");

        return "formType";
    }


    @RequestMapping("/saveType")
    public String saveType(@Valid Type type,
                            BindingResult bindingResult)
    {
        if (bindingResult.hasErrors()) return "formType";

        typeService.saveType(type);
        return "formType";
    }

    @RequestMapping("/ListeTypes")
    public String listeTypes(ModelMap modelMap,
                              @RequestParam (name="page",defaultValue = "0") int page,
                              @RequestParam (name="size", defaultValue = "2") int size)
    {
        Page<Type> typs = typeService.getAllTypesParPage(page, size);
        modelMap.addAttribute("type", typs);
        modelMap.addAttribute("pages", new int[typs.getTotalPages()]);
        modelMap.addAttribute("currentPage", page);
        return "listeTypes";
    }

    @RequestMapping("/supprimerType")
    public String supprimerType(@RequestParam("id") Long id,
                                 ModelMap modelMap,
                                 @RequestParam (name="page",defaultValue = "0") int page,
                                 @RequestParam (name="size", defaultValue = "2") int size)
    {
        typeService.deleteTypeById(id);
        Page<Type> typs = typeService.getAllTypesParPage(page,
                size);
        modelMap.addAttribute("types", typs);
        modelMap.addAttribute("pages", new int[typs.getTotalPages()]);
        modelMap.addAttribute("currentPage", page);
        modelMap.addAttribute("size", size);
        return "listeTypes";
    }
    @RequestMapping("/modifierType")
    public String editerType(@RequestParam("id") Long id, ModelMap modelMap) {
        Type type = typeService.getType(id);
        modelMap.addAttribute("type", type);
        modelMap.addAttribute("mode", "edit");
        return "formType";
    }



}
