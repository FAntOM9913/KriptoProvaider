import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class FileEncryptor extends JFrame {
    private JButton selectFileButton;
    private JButton saveFileButton;
    private File selectedFile;
    private SecretKey secretKey; // Симметричный ключ AES
    private JFileChooser fileChooser;
    private PrivateKey privateKey;

    public FileEncryptor() {
        setTitle("File Encryptor");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        selectFileButton = new JButton("Выберите файл для шифрования");
        saveFileButton = new JButton("Выберите куда сохранить файл");

        selectFileButton.addActionListener(new SelectFileAction());
        saveFileButton.addActionListener(new SaveFileAction());

        JPanel panel = new JPanel();
        panel.add(selectFileButton);
        panel.add(saveFileButton);
        add(panel);

        // Загружаем закрытый ключ RSA из файла
        loadPrivateKey();

        // Загружаем и расшифровываем AES ключ сразу после загрузки закрытого ключа
        loadAndDecryptAESKey();
        fileChooser = new JFileChooser();
    }

    // Метод для загрузки закрытого ключа RSA
    private void loadPrivateKey() {
        try {
            byte[] keyBytes = Files.readAllBytes(new File("private.enc").toPath());
            keyBytes = Base64.getDecoder().decode(new String(keyBytes)
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", ""));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error loading RSA private key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Метод для загрузки и расшифровки AES ключа
    private void loadAndDecryptAESKey() {
        try {
            byte[] encryptedKeyBytes = Files.readAllBytes(new File("aes_key.enc").toPath());
            secretKey = decryptKeyWithRSA(encryptedKeyBytes, privateKey);
            JOptionPane.showMessageDialog(this, "AES key decrypted successfully.");
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error decrypting AES key: " + ex.getMessage());
        }
    }

    private class SelectFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("All Files", "*.*"));
            int returnValue = fileChooser.showOpenDialog(FileEncryptor.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(FileEncryptor.this, "Selected file: " + selectedFile.getAbsolutePath());
            }
        }
    }

    private class SaveFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (selectedFile == null) {
                JOptionPane.showMessageDialog(FileEncryptor.this, "Please select a file to encrypt first.");
                return;
            }

            fileChooser.setFileFilter(new FileNameExtensionFilter("Encrypted Files", "*.enc"));
            int returnValue = fileChooser.showSaveDialog(FileEncryptor.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File saveFile = fileChooser.getSelectedFile();
                if (!saveFile.getAbsolutePath().endsWith(".enc")) {
                    saveFile = new File(saveFile.getAbsolutePath() + ".enc");
                }
                try {
                    encryptFile(selectedFile, saveFile);
                    JOptionPane.showMessageDialog(FileEncryptor.this, "File encrypted and saved to: " + saveFile.getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(FileEncryptor.this, "Error encrypting file: " + ex.getMessage());
                }
            }
        }
    }

    private void encryptFile(File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Считываем данные из входного файла
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Шифруем данные
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Записываем зашифрованные данные в выходной файл
        Files.write(outputFile.toPath(), outputBytes, StandardOpenOption.CREATE);
    }

    private SecretKey decryptKeyWithRSA(byte[] encryptedKeyBytes, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new FileEncryptor().setVisible(true);
        });
    }
}
