import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SignatureVerifier extends JFrame {
    private JButton selectHashButton;
    private JButton selectSignatureButton;
    private JButton selectPublicKeyButton;
    private JButton verifyButton;
    private File hashFile;
    private File signatureFile;
    private File publicKeyFile;
    private JFileChooser fileChooser;

    public SignatureVerifier() {
        setTitle("Проверка цифровой подписи");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        selectHashButton = new JButton("Выбрать файл с хеш-суммой");
        selectSignatureButton = new JButton("Выбрать файл с подписью");
        selectPublicKeyButton = new JButton("Выбрать файл с публичным ключом");
        verifyButton = new JButton("Проверить подпись");

        selectHashButton.addActionListener(new SelectHashFileAction());
        selectSignatureButton.addActionListener(new SelectSignatureFileAction());
        selectPublicKeyButton.addActionListener(new SelectPublicKeyFileAction());
        verifyButton.addActionListener(new VerifySignatureAction());

        JPanel panel = new JPanel();
        panel.add(selectHashButton);
        panel.add(selectSignatureButton);
        panel.add(selectPublicKeyButton);
        panel.add(verifyButton);
        add(panel);

        fileChooser = new JFileChooser();
    }

    private class SelectHashFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files", "*.txt"));
            int returnValue = fileChooser.showOpenDialog(SignatureVerifier.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                hashFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(SignatureVerifier.this, "Выбран файл с хеш-суммой: " + hashFile.getAbsolutePath());
            }
        }
    }

    private class SelectSignatureFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("Signature Files", "*.sig"));
            int returnValue = fileChooser.showOpenDialog(SignatureVerifier.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                signatureFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(SignatureVerifier.this, "Выбран файл с подписью: " + signatureFile.getAbsolutePath());
            }
        }
    }

    private class SelectPublicKeyFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("PEM Files", "*.pem"));
            int returnValue = fileChooser.showOpenDialog(SignatureVerifier.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                publicKeyFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(SignatureVerifier.this, "Выбран файл с публичным ключом: " + publicKeyFile.getAbsolutePath());
            }
        }
    }

    private class VerifySignatureAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (hashFile == null || signatureFile == null || publicKeyFile == null) {
                JOptionPane.showMessageDialog(SignatureVerifier.this, "Пожалуйста, выберите файл с хеш-суммой, файл с подписью и файл с публичным ключом.");
                return;
            }
            verifySignature();
        }
    }

    private void verifySignature() {
        try {
            // Считываем хеш-сумму из файла
            String hashValue = new String(Files.readAllBytes(hashFile.toPath())).trim();
            byte[] hashBytes = hexStringToByteArray(hashValue);

            // Считываем подпись из файла
            byte[] digitalSignature = Files.readAllBytes(signatureFile.toPath());

            // Считываем публичный ключ из PEM файла
            PublicKey publicKey = readPublicKeyFromPEM(publicKeyFile.getPath());

            // Проверка подписи
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(hashBytes);

            boolean isValid = signature.verify(digitalSignature);
            String message = isValid ? "Подпись действительна." : "Подпись недействительна.";
            JOptionPane.showMessageDialog(this, message);

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при проверке подписи: " + e.getMessage());
        }
    }

    private PublicKey readPublicKeyFromPEM(String filePath) throws Exception {
        String pem = new String(Files.readAllBytes(new File(filePath).toPath()));
        String publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
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
            new SignatureVerifier().setVisible(true);
        });
    }
}
