import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SignatureGenerator extends JFrame {
    private JButton selectHashButton;
    private JButton selectPrivateKeyButton;
    private JButton saveSignatureButton;
    private File hashFile;
    private File privateKeyFile;
    private JFileChooser fileChooser;

    public SignatureGenerator() {
        setTitle("Digital Signature Generator");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        selectHashButton = new JButton("Виберите файл с хэшем");
        selectPrivateKeyButton = new JButton("Выберите файл с приватным ключом");
        saveSignatureButton = new JButton("Выберите куда схранить подписаныый файл");

        selectHashButton.addActionListener(new SelectHashFileAction());
        selectPrivateKeyButton.addActionListener(new SelectPrivateKeyFileAction());
        saveSignatureButton.addActionListener(new SaveSignatureAction());

        JPanel panel = new JPanel();
        panel.add(selectHashButton);
        panel.add(selectPrivateKeyButton);
        panel.add(saveSignatureButton);
        add(panel);

        fileChooser = new JFileChooser();
    }

    private class SelectHashFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files", "*.txt"));
            int returnValue = fileChooser.showOpenDialog(SignatureGenerator.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                hashFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(SignatureGenerator.this, "Selected hash file: " + hashFile.getAbsolutePath());
            }
        }
    }

    private class SelectPrivateKeyFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("PEM Files", "*.pem"));
            int returnValue = fileChooser.showOpenDialog(SignatureGenerator.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                privateKeyFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(SignatureGenerator.this, "Selected private key file: " + privateKeyFile.getAbsolutePath());
            }
        }
    }

    private class SaveSignatureAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (hashFile == null || privateKeyFile == null) {
                JOptionPane.showMessageDialog(SignatureGenerator.this, "Please select both the hash file and the private key file.");
                return;
            }

            // Путь для сохранения подписи
            fileChooser.setFileFilter(new FileNameExtensionFilter("Signature Files", "*.sig"));
            int returnValue = fileChooser.showSaveDialog(SignatureGenerator.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File signatureFile = fileChooser.getSelectedFile();
                if (!signatureFile.getAbsolutePath().endsWith(".sig")) {
                    signatureFile = new File(signatureFile.getAbsolutePath() + ".sig");
                }
                generateDigitalSignature(signatureFile);
            }
        }
    }

    private void generateDigitalSignature(File signatureFile) {
        try {
            // Считываем хеш-сумму из файла
            String hashValue = new String(Files.readAllBytes(hashFile.toPath())).trim();
            byte[] hashBytes = hexStringToByteArray(hashValue);

            // Считываем закрытый ключ из PEM файла
            PrivateKey privateKey = readPrivateKeyFromPEM(privateKeyFile.getPath());

            // Создаем объект Signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(hashBytes);

            // Генерируем подпись
            byte[] digitalSignature = signature.sign();

            // Сохраняем подпись в файл
            Files.write(signatureFile.toPath(), digitalSignature);
            JOptionPane.showMessageDialog(this, "Signature successfully created and saved to: " + signatureFile.getAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error generating signature: " + e.getMessage());
        }
    }

    private PrivateKey readPrivateKeyFromPEM(String filePath) throws Exception {
        String pem = new String(Files.readAllBytes(new File(filePath).toPath()));
        String privateKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SignatureGenerator().setVisible(true);
        });
    }
}
