package com.tencent.wxcloudrun.controller;


import com.tencent.wxcloudrun.config.ApiResponse;
import com.tencent.wxcloudrun.service.CounterService;
import com.tencent.wxcloudrun.service.TigerTallyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


@RestController
public class TigerTallyController {
    final TigerTallyService myTigerTallyService;
    final Logger logger;

    public TigerTallyController(@Autowired CounterService counterService) throws IOException {
        this.myTigerTallyService = TigerTallyService.getInstance();
        this.logger = LoggerFactory.getLogger(CounterController.class);
    }

    // http://127.0.0.1/hello/unidbg
    @GetMapping("/hello/{name}")
    public String hello(@PathVariable("name") String name){
        return "你好，" + name + " !";
    }


    /**
     * 获取wtoken
     * @return API response json
     */
    @PostMapping(value = "/api/wtoken")
    public ApiResponse getWtoken(@RequestParam("payload") String payload) {
        logger.info("/api/wtoken get request");
        String wtoken = myTigerTallyService.avmpSign(payload, false);
        return ApiResponse.ok(wtoken);
    }
}
