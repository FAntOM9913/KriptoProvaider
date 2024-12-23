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

public class FileDecryptor extends JFrame {
    private JButton selectFileButton;
    private JButton saveFileButton;
    private File selectedFile;
    private SecretKey secretKey; // Симметричный ключ AES
    private JFileChooser fileChooser;
    private PrivateKey privateKey;

    public FileDecryptor() {
        setTitle("File Decryptor");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        selectFileButton = new JButton("Выберите файл для расшифровки");
        saveFileButton = new JButton("Выбирите куда сохранить файл");

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

    private void loadPrivateKey() {
        try {
            byte[] keyBytes = Files.readAllBytes(new File("private.enc").toPath());// ввести название вашего приватного ключа
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

    private void loadAndDecryptAESKey() {
        try {
            byte[] encryptedKeyBytes = Files.readAllBytes(new File("aes_key.enc").toPath()); // написать название для файла где хранится ключ AES
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
            fileChooser.setFileFilter(new FileNameExtensionFilter("Encrypted Files", "*.enc"));
            int returnValue = fileChooser.showOpenDialog(FileDecryptor.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(FileDecryptor.this, "Selected file: " + selectedFile.getAbsolutePath());
            }
        }
    }

    private class SaveFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (selectedFile == null) {
                JOptionPane.showMessageDialog(FileDecryptor.this, "Please select a file to decrypt first.");
                return;
            }

            fileChooser.setFileFilter(new FileNameExtensionFilter("Decrypted Files", "*.*"));
            int returnValue = fileChooser.showSaveDialog(FileDecryptor.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File saveFile = fileChooser.getSelectedFile();
                try {
                    decryptFile(selectedFile, saveFile); // Передаем файлы в метод
                    JOptionPane.showMessageDialog(FileDecryptor.this, "File decrypted and saved to: " + saveFile.getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(FileDecryptor.this, "Error decrypting file: " + ex.getMessage());
                }
            }
        }
    }

    private void decryptFile(File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Считываем зашифрованные данные из входного файла
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Расшифровываем данные
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Записываем расшифрованные данные в выходной файл
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
            new FileDecryptor().setVisible(true);
        });
    }
}
