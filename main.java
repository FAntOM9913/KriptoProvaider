import javax.swing.*;
import java.awt.*;

public class main extends JFrame {

    public main() {
        setTitle("Crypto Utility");
        setSize(300, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridLayout(9, 1)); // Увеличьте количество строк на 1 для новой кнопки

        JButton aesKeyGenButton = new JButton("Генерация AES ключа");
        JButton encryptButton = new JButton("Зашифровать файл");
        JButton decryptButton = new JButton("Расшифровать файл");
        JButton hashsumButton = new JButton("Вычислить Хэш-функцию");
        JButton keygenButton = new JButton("Сгенерировать пару ключей");
        JButton signButton = new JButton("Генерация электронной подписи");
        JButton verifyButton = new JButton("Проверка электронной подписи");
        JButton reEncryptButton = new JButton("Перешифровать AES ключ"); // Новая кнопка
        JButton privateKeyButton = new JButton("Расшифровать / Зашифровать приватный ключ"); // Новая кнопка

        aesKeyGenButton.addActionListener(e -> generateAesKey());
        encryptButton.addActionListener(e -> encryptFile());
        decryptButton.addActionListener(e -> decryptFile());
        hashsumButton.addActionListener(e -> computeHash());
        keygenButton.addActionListener(e -> generateKeys());
        signButton.addActionListener(e -> signFile());
        verifyButton.addActionListener(e -> verifySignature());
        reEncryptButton.addActionListener(e -> reEncryptKey()); // Привязка новой кнопки
        privateKeyButton.addActionListener(e -> openPrivateKeyDecryptor()); // Обработчик для новой кнопки

        add(aesKeyGenButton);
        add(encryptButton);
        add(decryptButton);
        add(hashsumButton);
        add(keygenButton);
        add(signButton);
        add(verifyButton);
        add(reEncryptButton); // Добавление кнопки в интерфейс
        add(privateKeyButton); // Добавление новой кнопки в интерфейс
    }

    private void openPrivateKeyDecryptor() {
        try {
            PrivateKeyDecryptor privateKeyDecryptor = new PrivateKeyDecryptor(); // Создаем экземпляр класса PrivateKeyDecryptor
            privateKeyDecryptor.setVisible(true); // Открываем интерфейс для работы с приватным ключом
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии дешифратора/шифатора ключа: " + e.getMessage());
        }
    }

    private void generateAesKey() {
        try {
            AesKeyGenerator aesKeyGenerator = new AesKeyGenerator(); // Создаем экземпляр класса AesKeyGenerator
            aesKeyGenerator.setVisible(true); // Открываем интерфейс для генерации AES ключа
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии генератора AES ключа: " + e.getMessage());
        }
    }

    private void computeHash() {
        try {
            FileHasher fileHasher = new FileHasher(); // Создаем экземпляр класса FileHasher
            fileHasher.setVisible(true); // Открываем интерфейс для вычисления хэш-функции
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии хэш-функции: " + e.getMessage());
        }
    }

    private void encryptFile() {
        try {
            FileEncryptor fileEncryptor = new FileEncryptor(); // Создаем экземпляр FileEncryptor
            fileEncryptor.setVisible(true);
            JOptionPane.showMessageDialog(this, "Шифратор открыт для работы!");
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии шифратора: " + e.getMessage());
        }
    }

    private void decryptFile() {
        try {
            FileDecryptor fileDecryptor = new FileDecryptor(); // Создаем экземпляр класса FileDecryptor
            fileDecryptor.setVisible(true); // Открываем интерфейс для расшифрования
            JOptionPane.showMessageDialog(this, "Дешифратор открыт для работы!");
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии дешифратора: " + e.getMessage());
        }
    }

    private void generateKeys() {
        try {
            String password = JOptionPane.showInputDialog(this, "Введите пароль для шифрования приватного ключа:");
            if (password != null && !password.trim().isEmpty()) {
                RSAKeyGenerator.generateRSAKeys(password); // Передача пароля в метод
                JOptionPane.showMessageDialog(this, "Пара ключей успешно сгенерирована!");
            } else {
                JOptionPane.showMessageDialog(this, "Пароль не введен. Генерация ключей отменена.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при генерации ключей: " + e.getMessage());
        }
    }

    private void signFile() {
        try {
            SignatureGenerator signatureGenerator = new SignatureGenerator(); // Создаем экземпляр класса SignatureGenerator
            signatureGenerator.setVisible(true); // Открываем интерфейс для генерации подписи
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии генерации подписи: " + e.getMessage());
        }
    }

    private void verifySignature() {
        try {
            SignatureVerifier signatureVerifier = new SignatureVerifier(); // Создаем экземпляр класса SignatureVerifier
            signatureVerifier.setVisible(true); // Открываем интерфейс для проверки подписи
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии проверки подписи: " + e.getMessage());
        }
    }

    private void reEncryptKey() {
        try {
            AesKeyReEncryptor reEncryptor = new AesKeyReEncryptor(); // Создаем экземпляр AesKeyReEncryptor
            reEncryptor.setVisible(true); // Открываем интерфейс для перешифрования AES ключа
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Ошибка при открытии перешифрования AES ключа: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            main app = new main();
            app.setVisible(true);
        });
    }
}
