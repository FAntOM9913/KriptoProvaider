import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.util.Base64;

public class RSAKeyGenerator {

    public static void generateRSAKeys(String password) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair pair = keyGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes("UTF-8"));

        byte[] keyAES = new byte[16];
        System.arraycopy(keyBytes, 0, keyAES, 0, Math.min(keyBytes.length, keyAES.length));

        SecretKeySpec secretKey = new SecretKeySpec(keyAES, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());

        try (FileOutputStream fos = new FileOutputStream("private.enc")) {
            fos.write(encryptedPrivateKey);
        }

        System.out.println("Приватный ключ зашифрован и сохранен в файл: private.enc");
    }

    public static void main(String[] args) throws Exception {
        String password = JOptionPane.showInputDialog("Введите пароль для шифрования приватного ключа:");
        if (password != null && !password.trim().isEmpty()) {
            generateRSAKeys(password);
        } else {
            System.out.println("Пароль не был введен. Программа завершена.");
        }
    }
}
