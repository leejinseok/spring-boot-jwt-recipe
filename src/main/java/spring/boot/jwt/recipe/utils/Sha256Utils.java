package spring.boot.jwt.recipe.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256Utils {

    private Sha256Utils() {}

    public static String hash(String value, String salt) {
        byte[] digest = digest(value, salt);
        return bytesToHex(digest);
    }

    public static String hash(String value) {
        byte[] digest = digest(value, null);
        return bytesToHex(digest);
    }

    public static byte[] digest(String value, String salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(value.getBytes());
            if (salt != null) {
                messageDigest.update(salt.getBytes());
            }
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
