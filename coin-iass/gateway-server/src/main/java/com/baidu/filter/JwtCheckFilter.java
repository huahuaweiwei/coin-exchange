package com.baidu.filter;

import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;

@Component
public class JwtCheckFilter implements GlobalFilter, Ordered {
    @Autowired
    private StringRedisTemplate redisTemplate;
    @Value("${no.require.urls:/admin/login}")
    private Set<String> noRequireTokenUris;

    /**
     * 过滤器拦截到用户的请求后做啥
     *  实现判断用户是否携带token ，或token 错误的功能
     *  1、先判断接口是否需要token才能访问
     *  2、取出用户的token
     *  3、判断用户的token是否有效
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1、先判断接口是否需要token才能访问
        if (!isRequireToken(exchange)){
            return chain.filter(exchange);  //不需要token，直接放行
        }
        //2、取出用户的token
        String token = getUserToken(exchange);
        //3、判断用户的token是否有效
        if (StringUtils.isEmpty(token)){
            return buildeNoAuthorizationResult(exchange);
        }
        //有效，将token存储到redis中
        Boolean hasKey = redisTemplate.hasKey(token);
        if (hasKey!=null && hasKey){
            return chain.filter(exchange);  //token有效，直接有效
        }

        return buildeNoAuthorizationResult(exchange);
    }

    //给用户响应一个没有token的错误
    private Mono<Void> buildeNoAuthorizationResult(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().set("Content-Type","application/json");
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error","NoAuthorization");
        jsonObject.put("errorMsg","Token is Null or Error");
        DataBuffer wrap = response.bufferFactory().wrap(jsonObject.toJSONString().getBytes());
        return response.writeWith(Flux.just(wrap));
    }

    //从 请求头中 获取用户的token
    private String getUserToken(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return token==null?null:token.replace("bearer","");
    }

    //判断该接口是否需要token
    private boolean isRequireToken(ServerWebExchange exchange) {
        //取出接口中的值
        String path = exchange.getRequest().getURI().getPath();
        //判断接口
        if (noRequireTokenUris.contains(path)){
            return false;  //不需要token
        }
        return Boolean.TRUE;  //需要token

    }

    //拦截器的顺序
    @Override
    public int getOrder() {
        return 0;
    }
}
