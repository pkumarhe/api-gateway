package com.pradeep.microservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

@Component
public class MyPrefilter implements GlobalFilter {
    final Logger logger= LoggerFactory.getLogger(MyPrefilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        logger.info("My first pre-filter is executed.............");
        String requestPath=exchange.getRequest().getPath().toString();
        logger.info("Request Path ............."+requestPath);
        HttpHeaders headers=exchange.getRequest().getHeaders();
        Set<String> headerNames=headers.keySet();
        headerNames.forEach((headerName)->{
            String headerValue=headers.getFirst(headerName);
            logger.info(headerName+" ............. "+headerValue);
        });
        return chain.filter(exchange);
    }
}