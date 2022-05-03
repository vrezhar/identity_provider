package am.ysu.identity.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Tools
{
    private static final Base64.Decoder base64Decoder = Base64.getUrlDecoder();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding(); //Required by RFC JWT standard

    public static String encodeToString(byte[] data){
        return base64Encoder.encodeToString(data);
    }

    public static byte[] encode(byte[] data){
        return base64Encoder.encode(data);
    }

    public static String encodeToString(String data){
        return encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] encode(String data){
        return encode(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decode(byte[] data){
        return base64Decoder.decode(data);
    }

    public static byte[] decode(String data){
        return base64Decoder.decode(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String decodeAsString(byte[] data){
        return new String(decode(data));
    }

    public static String decodeAsString(String data){
        return new String(decode(data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }
}
