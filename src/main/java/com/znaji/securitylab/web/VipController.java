package com.znaji.securitylab.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/vip")
public class VipController {

    @GetMapping("/status")
    public String vipStatus() {
        return "VIP status: this is a very secret page, only for VIP's";
    }
}
