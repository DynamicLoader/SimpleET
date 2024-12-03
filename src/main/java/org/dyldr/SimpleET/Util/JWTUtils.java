package org.dyldr.SimpleET.Util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

public class JWTUtils {

    // 这里可以使用生成的秘钥
    private static final String SECRET = "SimpleETSecretKey";

    /**
     * Generate token
     *
     * @param expire Expire Time, in minutes
     * @param map    payload
     * @return token string
     */
    public static String generateToken(int expire, Map<String, String> map) {
        // 设置有效期, 24 小时
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.SECOND, expire);

        // 创建 jwt 构造器
        JWTCreator.Builder builder = JWT.create();

        // 设置 payload
        map.forEach(builder::withClaim);

        // 设置过期时间, 生成 token
        return builder.withExpiresAt(instance.getTime()).sign(Algorithm.HMAC256(SECRET));
    }

    /**
     * verify token
     *
     * @param token token to be verified
     * @return DecodedJWT object
     */
    public static DecodedJWT verifyToken(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET))
                .build().verify(token);
    }
}