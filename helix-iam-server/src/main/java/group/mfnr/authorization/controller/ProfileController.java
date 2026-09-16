package group.mfnr.authorization.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfileController {


    @GetMapping("/me")
    public String registration(final Model model) {
        model.addAttribute("username", "-");
        model.addAttribute("firstName", "-");
        model.addAttribute("lastName", "-");
        model.addAttribute("mobilePhone", "-");

        return "me/profile";
    }
}
