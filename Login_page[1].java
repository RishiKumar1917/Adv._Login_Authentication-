import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.SecureRandom;
import java.util.Arrays;

public class Login_page extends JFrame {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JCheckBox showPassword;
    private JButton loginButton, signupButton;
    private HashMap<String, String> loginData = new HashMap<>();
    private int loginAttempts = 0;

    public Login_page() {

        String salt = "d6a6bc9bd8d9a7c5a6b8c9d0e1f2a3b";
        loginData.put("admin", hashPassword("Admin@123" + salt) + ":" + salt);

        setupUI();
        setTitle("Secure Login System");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
    }

    private void setupUI() {

        JPanel mainPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                Color color1 = new Color(55, 52, 226);
                Color color2 = new Color(84, 112, 255);
                GradientPaint gp = new GradientPaint(0, 0, color1, getWidth(), getHeight(), color2);
                g2d.setPaint(gp);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        mainPanel.setLayout(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));


        JLabel headerLabel = new JLabel("SECURE LOGIN", SwingConstants.CENTER);
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        headerLabel.setForeground(Color.WHITE);
        headerLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 20, 0));


        JPanel formPanel = new JPanel();
        formPanel.setOpaque(false);
        formPanel.setLayout(new GridLayout(3, 1, 10, 10));


        JPanel usernamePanel = createInputPanel("Username:", usernameField = new JTextField(15));


        JPanel passwordPanel = createInputPanel("Password:", passwordField = new JPasswordField(15));
        passwordPanel.add(showPassword = new JCheckBox("Show Password"));
        showPassword.addActionListener(e -> {
            passwordField.setEchoChar(showPassword.isSelected() ? (char) 0 : '*');
        });

        formPanel.add(usernamePanel);
        formPanel.add(passwordPanel);


        JPanel buttonPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        buttonPanel.setOpaque(false);
        loginButton = createStyledButton("Login", new Color(76, 101, 175));
        loginButton.addActionListener(new LoginAction());

        signupButton = createStyledButton("Sign Up", new Color(44, 33, 243));
        signupButton.addActionListener(e -> {
            SignupForm signupForm = new SignupForm(loginData);
            signupForm.setVisible(true); // Make the form visible
        });

        buttonPanel.add(loginButton);
        buttonPanel.add(signupButton);

        // Add components to main panel
        mainPanel.add(headerLabel, BorderLayout.NORTH);
        mainPanel.add(formPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(mainPanel);
    }

    private JPanel createInputPanel(String labelText, JComponent field) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        panel.setOpaque(false);
        JLabel label = new JLabel(labelText);
        label.setForeground(Color.WHITE);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        panel.add(label);

        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        field.setPreferredSize(new Dimension(200, 30));
        if (field instanceof JTextField) {
            ((JTextField) field).setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0, 3, 180)),
                    BorderFactory.createEmptyBorder(5, 10, 5, 10)
            ));
        } else if (field instanceof JPasswordField) {
            ((JPasswordField) field).setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0, 3, 180)),
                    BorderFactory.createEmptyBorder(5, 10, 5, 10)
            ));
        }
        panel.add(field);
        return panel;
    }

    private JButton createStyledButton(String text, Color bgColor) {
        // Make the color brighter by increasing RGB values
        Color brighterColor = new Color(
                Math.min(bgColor.getRed() + 40, 255),
                Math.min(bgColor.getGreen() + 40, 255),
                Math.min(bgColor.getBlue() + 40, 255)
        );

        JButton button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.BOLD, 14));
        button.setBackground(brighterColor); // Use brighter color
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        // Hover effect
        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                button.setBackground(brighterColor.darker());
            }
            @Override
            public void mouseExited(MouseEvent e) {
                button.setBackground(brighterColor);
            }
        });

        return button;
    }

    private class LoginAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String username = usernameField.getText();
            char[] passwordChars = passwordField.getPassword();
            String password = new String(passwordChars);
            Arrays.fill(passwordChars, '\0'); // Securely clear the password array

            if (loginData.containsKey(username)) {
                String storedValue = loginData.get(username);
                String[] parts = storedValue.split(":");
                if (parts.length != 2) {
                    showErrorMessage("Invalid user data");
                    return;
                }
                String storedHash = parts[0];
                String salt = parts[1];

                String hashedInput = hashPassword(password + salt);

                if (hashedInput.equals(storedHash)) {
                    logAttempt(username, true);
                    loginAttempts = 0;
                    showSuccessMessage();
                } else {
                    loginAttempts++;
                    logAttempt(username, false);
                    if (loginAttempts >= 3) {
                        JOptionPane.showMessageDialog(Login_page.this,
                                "Too many failed attempts. System will exit.",
                                "Security Alert", JOptionPane.ERROR_MESSAGE);
                        System.exit(0);
                    } else {
                        showErrorMessage("Incorrect password. Attempts left: " + (3 - loginAttempts));
                    }
                }
            } else {
                logAttempt(username, false);
                showErrorMessage("Username not found");
            }
        }
    }

    private void showSuccessMessage() {
        JOptionPane.showMessageDialog(this,
                "Login Successful!\nWelcome back.",
                "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showErrorMessage(String message) {
        JOptionPane.showMessageDialog(this,
                message,
                "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void logAttempt(String username, boolean success) {
        String status = success ? "SUCCESS" : "FAILURE";
        String timeStamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String log = String.format("User: %s | Time: %s | Status: %s%n", username, timeStamp, status);

        try (FileWriter fw = new FileWriter("login_audit_log.txt", true)) {
            fw.write(log);
        } catch (IOException ex) {
            System.out.println("Log error: " + ex.getMessage());
        }
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    class SignupForm extends JFrame {
        private JTextField newUserField;
        private JPasswordField newPassField;
        private JButton registerButton;
        private JLabel strengthLabel;
        private JProgressBar strengthBar;

        SignupForm(HashMap<String, String> loginData) {
            setTitle("Secure Sign Up");
            setSize(450, 300);
            setLocationRelativeTo(null);
            setResizable(false);
            setupUI(loginData);
        }

        private void setupUI(HashMap<String, String> loginData) {
            JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
            mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
            mainPanel.setBackground(Color.WHITE);

            JLabel headerLabel = new JLabel("CREATE NEW ACCOUNT", SwingConstants.CENTER);
            headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
            headerLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 20, 0));

            JPanel formPanel = new JPanel(new GridLayout(3, 1, 10, 10));
            formPanel.setBackground(Color.WHITE);

            // Username field
            JPanel usernamePanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
            usernamePanel.setBackground(Color.WHITE);
            usernamePanel.add(new JLabel("Username:"));
            newUserField = new JTextField(15);
            newUserField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            usernamePanel.add(newUserField);

            // Password field with strength meter
            JPanel passwordPanel = new JPanel(new BorderLayout(5, 5));
            passwordPanel.setBackground(Color.WHITE);

            JPanel passInputPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
            passInputPanel.setBackground(Color.WHITE);
            passInputPanel.add(new JLabel("Password:"));
            newPassField = new JPasswordField(15);
            newPassField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            passInputPanel.add(newPassField);

            // Strength indicator
            JPanel strengthPanel = new JPanel(new BorderLayout(5, 5));
            strengthPanel.setBackground(Color.WHITE);
            strengthLabel = new JLabel(" ", SwingConstants.CENTER);
            strengthLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));

            strengthBar = new JProgressBar(0, 100);
            strengthBar.setStringPainted(false);
            strengthBar.setForeground(Color.RED);
            strengthBar.setBackground(new Color(0, 3, 180));
            strengthBar.setPreferredSize(new Dimension(200, 8));

            strengthPanel.add(strengthLabel, BorderLayout.NORTH);
            strengthPanel.add(strengthBar, BorderLayout.CENTER);

            passwordPanel.add(passInputPanel, BorderLayout.NORTH);
            passwordPanel.add(strengthPanel, BorderLayout.CENTER);

            // Requirements label
            JLabel reqLabel = new JLabel("<html><small>Password must contain: 8+ chars, uppercase, lowercase, number, symbol</small></html>");
            reqLabel.setFont(new Font("Segoe UI", Font.PLAIN, 10));
            reqLabel.setForeground(Color.GRAY);
            reqLabel.setHorizontalAlignment(SwingConstants.CENTER);
            passwordPanel.add(reqLabel, BorderLayout.SOUTH);

            formPanel.add(usernamePanel);
            formPanel.add(passwordPanel);

            // Button panel
            JPanel buttonPanel = new JPanel();
            buttonPanel.setBackground(Color.WHITE);
            // Use same brighter color logic as in main class
            Color baseColor = new Color(76, 175, 80);
            Color brighterColor = new Color(
                    Math.min(baseColor.getRed() + 40, 255),
                    Math.min(baseColor.getGreen() + 40, 255),
                    Math.min(baseColor.getBlue() + 40, 255)
            );

            registerButton = new JButton("Register");
            registerButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
            registerButton.setBackground(brighterColor);
            registerButton.setForeground(Color.WHITE);
            registerButton.setFocusPainted(false);
            registerButton.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
            registerButton.setCursor(new Cursor(Cursor.HAND_CURSOR));

            // Hover effect
            registerButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    registerButton.setBackground(brighterColor.darker());
                }
                @Override
                public void mouseExited(MouseEvent e) {
                    registerButton.setBackground(brighterColor);
                }
            });

            registerButton.addActionListener(e -> registerUser(loginData));
            buttonPanel.add(registerButton);

            // Password strength listener
            newPassField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void changedUpdate(javax.swing.event.DocumentEvent e) { updateStrength(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { updateStrength(); }
                public void insertUpdate(javax.swing.event.DocumentEvent e) { updateStrength(); }
            });

            mainPanel.add(headerLabel, BorderLayout.NORTH);
            mainPanel.add(formPanel, BorderLayout.CENTER);
            mainPanel.add(buttonPanel, BorderLayout.SOUTH);

            add(mainPanel);
        }

        private void registerUser(HashMap<String, String> loginData) {
            String newUser = newUserField.getText().trim();
            char[] passwordChars = newPassField.getPassword();
            String newPass = new String(passwordChars);
            Arrays.fill(passwordChars, '\0'); // Securely clear the password array

            if (newUser.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Username cannot be empty", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (loginData.containsKey(newUser)) {
                JOptionPane.showMessageDialog(this, "Username already exists", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!isStrongPassword(newPass)) {
                JOptionPane.showMessageDialog(this,
                        "<html>Password must contain:<br>" +
                                "- At least 8 characters<br>" +
                                "- Uppercase letter<br>" +
                                "- Lowercase letter<br>" +
                                "- Number<br>" +
                                "- Special character</html>",
                        "Weak Password", JOptionPane.WARNING_MESSAGE);
                return;
            }

            String salt = generateSalt();
            String hashedPassword = hashPassword(newPass + salt);
            loginData.put(newUser, hashedPassword + ":" + salt);

            JOptionPane.showMessageDialog(this,
                    "Registration successful!\nYour account has been created.",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            this.dispose();
        }

        private boolean isStrongPassword(String pass) {
            return pass.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!]).{8,}$");
        }

        private String generateSalt() {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            StringBuilder sb = new StringBuilder();
            for (byte b : salt) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        private void updateStrength() {
            char[] passwordChars = newPassField.getPassword();
            String pass = new String(passwordChars);
            Arrays.fill(passwordChars, '\0');

            int strength = calculatePasswordStrength(pass);

            strengthBar.setValue(strength);

            if (strength < 30) {
                strengthBar.setForeground(Color.RED);
                strengthLabel.setText("Weak");
                strengthLabel.setForeground(Color.RED);
            } else if (strength < 70) {
                strengthBar.setForeground(Color.ORANGE);
                strengthLabel.setText("Medium");
                strengthLabel.setForeground(Color.ORANGE);
            } else {
                strengthBar.setForeground(new Color(0, 132, 180));
                strengthLabel.setText("Strong");
                strengthLabel.setForeground(new Color(0, 132, 180));
            }
        }

        private int calculatePasswordStrength(String password) {
            int strength = 0;

            // Length (max 50 points)
            strength += Math.min(50, password.length() * 5);

            // Character variety
            boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;

            for (char c : password.toCharArray()) {
                if (Character.isUpperCase(c)) hasUpper = true;
                if (Character.isLowerCase(c)) hasLower = true;
                if (Character.isDigit(c)) hasDigit = true;
                if (!Character.isLetterOrDigit(c)) hasSpecial = true;
            }

            if (hasUpper) strength += 10;
            if (hasLower) strength += 10;
            if (hasDigit) strength += 10;
            if (hasSpecial) strength += 20;

            return Math.min(100, strength);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }

            Login_page loginSystem = new Login_page();
            loginSystem.setVisible(true);
        });
    }
}