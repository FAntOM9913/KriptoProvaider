import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;

public class PrivateKeyDecryptor extends JFrame {

    private JButton decryptButton;
    private JButton encryptButton;

    public PrivateKeyDecryptor() {
        setTitle("Decrypt and Re-encrypt Private Key");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        decryptButton = new JButton("Decrypt Private Key");
        encryptButton = new JButton("Encrypt Private Key");

        decryptButton.addActionListener(e -> decryptPrivateKeyAction());
        encryptButton.addActionListener(e -> encryptPrivateKeyAction());

        add(decryptButton);
        add(encryptButton);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new PrivateKeyDecryptor().setVisible(true);
        });
    }

    private void decryptPrivateKeyAction() {
        // Запрашиваем у пользователя пароль
        String password = JOptionPane.showInputDialog("Введите пароль для расшифровки приватного ключа:");
        if (password == null || password.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Пароль не должен быть пустым. Программа завершена.");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл с зашифрованным приватным ключом");
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue != JFileChooser.APPROVE_OPTION) {
            JOptionPane.showMessageDialog(this, "Файл не был выбран. Программа завершена.");
            return;
        }

        File encryptedPrivateKeyFile = fileChooser.getSelectedFile();

        try {
            // Расшифровка приватного ключа
            byte[] encryptedKeyBytes = Files.readAllBytes(encryptedPrivateKeyFile.toPath());
            byte[] decryptedKeyBytes = decryptPrivateKey(encryptedKeyBytes, password);

            saveDecryptedPrivateKey(decryptedKeyBytes, "private.enc");

            JOptionPane.showMessageDialog(this, "Приватный ключ успешно расшифрован и сохранен в файл: private.enc");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Ошибка при расшифровке приватного ключа: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void encryptPrivateKeyAction() {
        // Запрашиваем у пользователя пароль
        String password = JOptionPane.showInputDialog("Введите пароль для шифрования приватного ключа:");
        if (password == null || password.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Пароль не должен быть пустым. Программа завершена.");
            return;
        }

        // Запрашиваем файл с расшифрованным приватным ключом
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл с расшифрованным приватным ключом");
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue != JFileChooser.APPROVE_OPTION) {
            JOptionPane.showMessageDialog(this, "Файл не был выбран. Программа завершена.");
            return;
        }

        File privateKeyFile = fileChooser.getSelectedFile();

        try {
            // Чтение расшифрованного приватного ключа
            byte[] decryptedKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            byte[] encryptedKeyBytes = encryptPrivateKey(decryptedKeyBytes, password);

            // Сохранение зашифрованного приватного ключа в файл
            saveEncryptedPrivateKey(encryptedKeyBytes, "private.enc");

            JOptionPane.showMessageDialog(this, "Приватный ключ успешно зашифрован и сохранен в файл: private.enc");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Ошибка при шифровании приватного ключа: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Метод для расшифровки приватного ключа
    public static byte[] decryptPrivateKey(byte[] keyBytes, String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes("UTF-8"));

        byte[] keyAES = new byte[16];
        System.arraycopy(key, 0, keyAES, 0, Math.min(key.length, keyAES.length));

        SecretKeySpec secretKey = new SecretKeySpec(keyAES, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(keyBytes);
    }

    // Метод для сохранения расшифрованного приватного ключа в файл
    public static void saveDecryptedPrivateKey(byte[] decryptedKeyBytes, String filename) throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(decryptedKeyBytes) +
                "\n-----END PRIVATE KEY-----";
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(pem.getBytes());
        }
    }

    // Метод для шифрования приватного ключа
    public static byte[] encryptPrivateKey(byte[] keyBytes, String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes("UTF-8"));

        byte[] keyAES = new byte[16];
        System.arraycopy(key, 0, keyAES, 0, Math.min(key.length, keyAES.length));

        SecretKeySpec secretKey = new SecretKeySpec(keyAES, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(keyBytes);
    }

    // Метод для сохранения зашифрованного приватного ключа в файл
    public static void saveEncryptedPrivateKey(byte[] encryptedKeyBytes, String filename) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(encryptedKeyBytes);
        }
    }
}
