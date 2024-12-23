import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AesKeyGenerator extends JFrame {
    private File publicKeyFile; // Файл открытого ключа

    public AesKeyGenerator() {
        setTitle("Генерация AES ключа");
        setSize(400, 200);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        JButton chooseKeyButton = new JButton("Выбрать публичный ключ");
        chooseKeyButton.addActionListener(e -> choosePublicKeyFile());

        JButton generateButton = new JButton("Сгенерировать AES ключ");
        generateButton.addActionListener(e -> generateKey());

        getContentPane().setLayout(new FlowLayout());
        getContentPane().add(chooseKeyButton);
        getContentPane().add(generateButton);
    }

    private void choosePublicKeyFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл публичного ключа");
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            publicKeyFile = fileChooser.getSelectedFile();
            showMessage("Выбран файл: " + publicKeyFile.getAbsolutePath());
        }
    }

    private void generateKey() {
        if (publicKeyFile == null) {
            showMessage("Пожалуйста, выберите публичный ключ перед генерацией.");
            return;
        }

        try {
            SecretKey secretKey = generateAesKey(256); // 128, 192, или 256 бит

            PublicKey publicKey = loadPublicKey(publicKeyFile);

            byte[] encryptedKey = encryptKeyWithRSA(secretKey.getEncoded(), publicKey);

            String filename = "aes_key.enc";
            saveKeyToFile(encryptedKey, filename);

            showMessage("Симметричный ключ AES успешно сгенерирован и зашифрован. Файл сохранен: " + filename);
        } catch (Exception e) {
            showMessage("Ошибка при генерации ключа AES: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static SecretKey generateAesKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public PublicKey loadPublicKey(File file) throws Exception {
        // Чтение открытого RSA ключа из файла
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        keyBytes = Base64.getDecoder().decode(new String(keyBytes)
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", ""));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static byte[] encryptKeyWithRSA(byte[] keyToEncrypt, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(keyToEncrypt);
    }

    public static void saveKeyToFile(byte[] keyBytes, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(keyBytes);
        }
    }

    // Метод для отображения сообщения
    private static void showMessage(String message) {
        JOptionPane.showMessageDialog(null, message, "Результат", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new AesKeyGenerator().setVisible(true);
        });
    }
}
