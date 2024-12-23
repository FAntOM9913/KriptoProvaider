import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AesKeyReEncryptor extends JFrame {
    private File encryptedAesKeyFile;
    private File publicKeyFile;
    private PrivateKey privateKey;

    public AesKeyReEncryptor() {
        setTitle("Перешифрование AES ключа");
        setSize(400, 300);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        JButton chooseEncryptedKeyButton = new JButton("Выбрать зашифрованный AES ключ");
        chooseEncryptedKeyButton.addActionListener(e -> chooseEncryptedKeyFile());

        JButton choosePublicKeyButton = new JButton("Выбрать публичный ключ");
        choosePublicKeyButton.addActionListener(e -> choosePublicKeyFile());

        JButton reEncryptButton = new JButton("Перешифровать AES ключ");
        reEncryptButton.addActionListener(e -> reEncryptKey());

        getContentPane().setLayout(new FlowLayout());
        getContentPane().add(chooseEncryptedKeyButton);
        getContentPane().add(choosePublicKeyButton);
        getContentPane().add(reEncryptButton);

        // Загрузка приватного ключа из файла при инициализации
        loadPrivateKey();
    }

    private void loadPrivateKey() {
        try {
            File privateKeyFile = new File("private.pem");
            privateKey = loadPrivateKey(privateKeyFile);
            showMessage("Приватный ключ успешно загружен: " + privateKeyFile.getAbsolutePath());
        } catch (Exception e) {
            showMessage("Ошибка при загрузке приватного ключа: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void chooseEncryptedKeyFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл с зашифрованным AES ключом");
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            encryptedAesKeyFile = fileChooser.getSelectedFile();
            showMessage("Выбран файл зашифрованного AES ключа: " + encryptedAesKeyFile.getAbsolutePath());
        }
    }

    private void choosePublicKeyFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Выберите файл публичного ключа");
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            publicKeyFile = fileChooser.getSelectedFile();
            showMessage("Выбран файл публичного ключа: " + publicKeyFile.getAbsolutePath());
        }
    }

    private void reEncryptKey() {
        if (encryptedAesKeyFile == null || publicKeyFile == null) {
            showMessage("Пожалуйста, выберите файлы с зашифрованным AES ключом и публичным ключом.");
            return;
        }

        try {
            // 1. Чтение зашифрованного AES ключа из файла
            byte[] encryptedKeyBytes = Files.readAllBytes(encryptedAesKeyFile.toPath());

            // 2. Расшифровка AES ключа с помощью приватного ключа
            byte[] decryptedKeyBytes = decryptAESKey(encryptedKeyBytes, privateKey);

            // 3. Загрузка публичного ключа
            PublicKey publicKey = loadPublicKey(publicKeyFile);

            // 4. Шифрование AES ключа с использованием нового публичного ключа
            byte[] newEncryptedKey = encryptKeyWithRSA(decryptedKeyBytes, publicKey);

            // 5. Сохранение нового зашифрованного ключа в файл
            String outputFilename = "new_encrypted_aes_key.enc";
            saveKeyToFile(newEncryptedKey, outputFilename);

            showMessage("AES ключ успешно перешифрован. Новый файл: " + outputFilename);
        } catch (Exception e) {
            showMessage("Ошибка при перешифровании AES ключа: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Метод для загрузки публичного ключа из файла
    public PublicKey loadPublicKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        keyBytes = Base64.getDecoder().decode(new String(keyBytes)
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", ""));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // Метод для загрузки приватного ключа из файла
    public PrivateKey loadPrivateKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        keyBytes = Base64.getDecoder().decode(new String(keyBytes)
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", ""));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // Метод для расшифровки AES ключа
    public byte[] decryptAESKey(byte[] encryptedKeyBytes, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    // Метод для шифрования AES ключа с помощью публичного ключа
    public static byte[] encryptKeyWithRSA(byte[] keyToEncrypt, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(keyToEncrypt);
    }

    // Метод для сохранения зашифрованного ключа в файл
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
            new AesKeyReEncryptor().setVisible(true);
        });
    }
}