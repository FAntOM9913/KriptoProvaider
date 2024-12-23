import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileHasher extends JFrame {
    private JButton selectFileButton;
    private JButton saveHashButton;
    private JButton checkIntegrityButton;
    private File selectedFile;
    private JFileChooser fileChooser;

    public FileHasher() {
        setTitle("File Hasher");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        selectFileButton = new JButton("Выберите файл для вычисления хэша");
        saveHashButton = new JButton("Выберите куда сохраните файл");
        checkIntegrityButton = new JButton("Проверить файл на целостность");

        selectFileButton.addActionListener(new SelectFileAction());
        saveHashButton.addActionListener(new SaveHashAction());
        checkIntegrityButton.addActionListener(new CheckIntegrityAction());

        JPanel panel = new JPanel();
        panel.add(selectFileButton);
        panel.add(saveHashButton);
        panel.add(checkIntegrityButton);
        add(panel);

        fileChooser = new JFileChooser();
    }

    // Метод для вычисления хеш-суммы файла
    private String calculateHash(String filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] byteArray = new byte[1024];
            int bytesCount;

            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : digest.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Метод для сохранения хеш-суммы в файл
    private void saveHashToFile(String hash, String hashFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(hashFilePath)) {
            fos.write(hash.getBytes(StandardCharsets.UTF_8));
        }
    }

    // Метод для проверки целостности файла
    private boolean checkFileIntegrity(String hashFilePath1, String hashFilePath2) throws IOException {
        String hash1;
        String hash2;

        try (FileInputStream fis1 = new FileInputStream(hashFilePath1)) {
            byte[] hashBytes1 = new byte[fis1.available()];
            fis1.read(hashBytes1);
            hash1 = new String(hashBytes1, StandardCharsets.UTF_8);
        }

        try (FileInputStream fis2 = new FileInputStream(hashFilePath2)) {
            byte[] hashBytes2 = new byte[fis2.available()];
            fis2.read(hashBytes2);
            hash2 = new String(hashBytes2, StandardCharsets.UTF_8);
        }

        return hash1.equals(hash2);
    }

    private class SelectFileAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            fileChooser.setFileFilter(new FileNameExtensionFilter("All Files", "*.*"));
            int returnValue = fileChooser.showOpenDialog(FileHasher.this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile();
                JOptionPane.showMessageDialog(FileHasher.this, "Selected file: " + selectedFile.getAbsolutePath());
            }
        }
    }

    private class SaveHashAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (selectedFile == null) {
                JOptionPane.showMessageDialog(FileHasher.this, "Please select a file to hash first.");
                return;
            }

            String hash;
            try {
                hash = calculateHash(selectedFile.getAbsolutePath());
                fileChooser.setDialogTitle("Save Hash File");
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                int returnValue = fileChooser.showSaveDialog(FileHasher.this);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File saveFile = fileChooser.getSelectedFile();
                    if (!saveFile.getAbsolutePath().endsWith(".hash")) {
                        saveFile = new File(saveFile.getAbsolutePath() + ".hash");
                    }
                    saveHashToFile(hash, saveFile.getAbsolutePath());
                    JOptionPane.showMessageDialog(FileHasher.this, "Hash saved to: " + saveFile.getAbsolutePath());
                }
            } catch (IOException | NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(FileHasher.this, "Error calculating or saving hash: " + ex.getMessage());
            }
        }
    }

    private class CheckIntegrityAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String hashFilePath1 = null;
            String hashFilePath2 = null;

            // Выбор первого файла хеш-суммы
            fileChooser.setFileFilter(new FileNameExtensionFilter("Hash Files", "*.hash"));
            int returnValue1 = fileChooser.showOpenDialog(FileHasher.this);
            if (returnValue1 == JFileChooser.APPROVE_OPTION) {
                hashFilePath1 = fileChooser.getSelectedFile().getAbsolutePath();
                JOptionPane.showMessageDialog(FileHasher.this, "Selected hash file: " + hashFilePath1);
            }

            // Выбор второго файла хеш-суммы
            int returnValue2 = fileChooser.showOpenDialog(FileHasher.this);
            if (returnValue2 == JFileChooser.APPROVE_OPTION) {
                hashFilePath2 = fileChooser.getSelectedFile().getAbsolutePath();
                JOptionPane.showMessageDialog(FileHasher.this, "Selected hash file: " + hashFilePath2);
            }

            // Проверка целостности
            if (hashFilePath1 != null && hashFilePath2 != null) {
                try {
                    if (checkFileIntegrity(hashFilePath1, hashFilePath2)) {
                        JOptionPane.showMessageDialog(FileHasher.this, "Hash files are identical.");
                    } else {
                        JOptionPane.showMessageDialog(FileHasher.this, "Hash files are different.");
                    }
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(FileHasher.this, "Error checking integrity: " + ex.getMessage());
                }
            } else {
                JOptionPane.showMessageDialog(FileHasher.this, "Please select both hash files to compare.");
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new FileHasher().setVisible(true);
        });
    }
}
