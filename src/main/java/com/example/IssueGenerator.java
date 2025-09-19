
package com.example;

import java.io.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.security.SecureRandom;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

/**
 * A class that generates various code scenarios for testing and analysis.
 * This class implements secure coding practices and proper error handling.
 */
public class IssueGenerator {
    // Hardcoded credentials - security hotspot
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk_live_12345";
    
    // Public static fields - code smell
    public static String ENVIRONMENT = "production";
    public static boolean DEBUG_MODE = true;
    
    // Weak encryption key - security vulnerability
    private static final String ENCRYPTION_KEY = "1234567890abcdef";
    
    // Hardcoded IP and port - security hotspot
    private static final String SERVER_ADDRESS = "192.168.1.100";
    private static final int SERVER_PORT = 3306;
    
    private static final Logger LOGGER = Logger.getLogger(IssueGenerator.class.getName());
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private final String environment;
    private final boolean debugMode;
    
    // Unused fields - code smell
    private String unusedField1;
    private int unusedField2;

    public IssueGenerator() {
        this.environment = System.getenv().getOrDefault("APP_ENV", "development");
        this.debugMode = Boolean.parseBoolean(System.getenv().getOrDefault("DEBUG_MODE", "false"));
    }

    private static final int MATRIX_SIZE = 3000;
    private static final int ITERATION_COUNT = 20000;
    private static final int SLEEP_TIME = 200;
    private static final int FILE_SIZE = 10 * 1024 * 1024; // 10MB
    
    public static void main(String[] args) {
        IssueGenerator generator = new IssueGenerator();
        
        // Larger array for more memory consumption
        double[][][] largeArray = new double[MATRIX_SIZE][MATRIX_SIZE][3];
        java.util.List<String> memoryList = new java.util.ArrayList<>();
        
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            // Increased iterations significantly
            for (int i = 0; i < ITERATION_COUNT; i++) {
                try {
                    // Even more complex 3D matrix operations
                    for (int j = 0; j < MATRIX_SIZE; j++) {
                        for (int k = 0; k < MATRIX_SIZE; k++) {
                            double angle = Math.toRadians(i + j + k);
                            // Complex calculations for each cell
                            largeArray[j][k][0] = Math.sin(angle) * Math.cos(angle) * Math.tan(angle);
                            largeArray[j][k][1] = Math.pow(Math.E, Math.sin(angle)) * Math.log(Math.abs(angle) + 1);
                            largeArray[j][k][2] = Math.sqrt(Math.abs(Math.cos(angle))) * Math.cbrt(Math.abs(Math.sin(angle)));
                            
                            // Additional computations
                            for (int l = 0; l < 10; l++) {
                                double temp = Math.pow(largeArray[j][k][0], 2) + Math.pow(largeArray[j][k][1], 2);
                                largeArray[j][k][2] += Math.sqrt(temp) * Math.log(Math.abs(temp) + 1);
                            }
                        }
                    }
                    
                    // Memory-consuming string operations
                    StringBuilder sb = new StringBuilder();
                    for (int m = 0; m < 1000; m++) {
                        sb.append(java.util.UUID.randomUUID().toString());
                    }
                    memoryList.add(sb.toString());
                    
                    // Intensive mathematical computations
                    double accumulator = 0.0;
                    for (int j = 0; j < 2000; j++) {
                        for (int k = 0; k < 2000; k++) {
                            double x = Math.sin(i * Math.PI / 180.0);
                            double y = Math.cos(j * Math.PI / 180.0);
                            double z = Math.tan(k * Math.PI / 180.0);
                            
                            accumulator += Math.pow(x * y * z, 3) + 
                                          Math.sqrt(Math.abs(Math.log(Math.abs(x) + 1))) + 
                                          Math.cbrt(Math.abs(Math.sin(y * z)));
                        }
                    }
                    
                    // Prime number calculation (intensive CPU operation)
                    for (int num = i * 1000; num < (i + 1) * 1000; num++) {
                        boolean isPrime = true;
                        for (int j = 2; j <= Math.sqrt(num); j++) {
                            if (num % j == 0) {
                                isPrime = false;
                                break;
                            }
                        }
                        if (isPrime) {
                            accumulator += num;
                        }
                    }
                    
                    generator.generateIssues(i);
                    
                    // Increased sleep time
                    Thread.sleep(SLEEP_TIME);
                    
                    // Intensive file I/O operations
                    for (int fileNum = 0; fileNum < 20; fileNum++) {
                        String tempFile = "temp_" + i + "_" + fileNum + ".txt";
                        try (java.io.FileWriter writer = new java.io.FileWriter(tempFile)) {
                            // Write very large amount of data
                            byte[] data = new byte[FILE_SIZE];
                            new SecureRandom().nextBytes(data);
                            
                            // Convert bytes to Base64 for more processing
                            String base64Data = Base64.getEncoder().encodeToString(data);
                            
                            // Write in chunks with additional processing
                            int chunkSize = 1024;
                            for (int pos = 0; pos < base64Data.length(); pos += chunkSize) {
                                String chunk = base64Data.substring(
                                    pos, Math.min(pos + chunkSize, base64Data.length())
                                );
                                // Add some processing overhead
                                chunk = chunk.chars()
                                    .mapToObj(ch -> String.format("%02x", ch))
                                    .collect(java.util.stream.Collectors.joining());
                                writer.write(chunk);
                                writer.write("\n");
                            }
                        }
                        
                        // Read the file back
                        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(tempFile))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                // Process each line
                                line.chars().forEach(ch -> {
                                    Math.sin(ch); // Unnecessary computation for each character
                                });
                            }
                        }
                        
                        // Delete the file
                        new java.io.File(tempFile).delete();
                    }
                    
                    // Increased network-like delay simulation
                    if (i % 50 == 0) {
                        Thread.sleep(1000); // Longer network latency simulation
                    }
                    
                    // Additional CPU-intensive task
                    if (i % 10 == 0) {
                        // Calculate prime numbers
                        for (int n = 2; n < 100000; n++) {
                            boolean isPrime = true;
                            for (int j = 2; j <= Math.sqrt(n); j++) {
                                if (n % j == 0) {
                                    isPrime = false;
                                    break;
                                }
                            }
                            if (isPrime) {
                                // Do some work with the prime number
                                double result = Math.pow(n, 1.0/3) * Math.log(n);
                            }
                        }
                    }
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.log(Level.WARNING, "Process interrupted", e);
                    break;
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error in main loop", e);
                }
            }
        }
    }

    /**
     * Generates various code scenarios with proper security and error handling.
     * @param index The iteration index
     * @throws Exception If any error occurs during processing
     */
    public void generateIssues(int index) throws Exception {
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE id = " + index;
        executeQuery(query);
        
        // Command injection vulnerability
        String command = "ping " + SERVER_ADDRESS;
        Runtime.getRuntime().exec(command);
        
        // Path traversal vulnerability
        String filePath = "../user_files/" + index + "/data.txt";
        java.io.File file = new java.io.File(filePath);
        
        // XSS vulnerability
        String userInput = "<script>alert('xss')</script>";
        System.out.println("User input: " + userInput);
        
        // Weak random number generator
        java.util.Random random = new java.util.Random();
        int randomValue = random.nextInt();
        
        // Empty catch block
        try {
            riskyOperation();
        } catch (Exception e) {
            // Do nothing
        }

        // Using prepared statements to prevent SQL injection
        String input = "some_input";
        executeSafeQuery("SELECT * FROM users WHERE name = ?", input);

        // Proper resource management with try-with-resources
        try (BufferedReader reader = new BufferedReader(
                new FileReader("config.properties"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                processConfigLine(line);
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading configuration", e);
            throw e;
        }

        // Secure system property handling
        setSecureSystemProperty("java.security.krb5.realm", 
            System.getenv("KRB5_REALM"));

        // Complex processing for thorough scanning
        processSecureData(index);
    }

    /**
     * Executes a SQL query safely using prepared statements.
     * @param query The SQL query template
     * @param params The query parameters
     * @throws SQLException If a database error occurs
     */
    private void executeSafeQuery(String query, Object... params) throws SQLException {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            for (int i = 0; i < params.length; i++) {
                stmt.setObject(i + 1, params[i]);
            }
            stmt.executeQuery();
        }
    }

    /**
     * Hashes a password securely using PBKDF2.
     * @param password The password to hash
     * @param salt The salt for the hash
     * @return The hashed password
     */
    private String hashPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Sets a system property securely with validation.
     * @param key The property key
     * @param value The property value
     */
    public void setSecureSystemProperty(String key, String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Property value cannot be empty");
        }
        System.setProperty(key, value);
    }

    /**
     * Processes configuration data securely.
     * @param line The configuration line to process
     */
    private void processConfigLine(String line) {
        if (line != null && !line.trim().isEmpty()) {
            // Implement secure configuration processing
            LOGGER.info("Processing config: " + line);
        }
    }

    /**
     * Performs complex calculations for thorough scanning.
     * @param index The iteration index
     */
    private void processComplexCalculation(int index) {
        double result = 0;
        for (int i = 0; i < 1000; i++) {
            result += Math.pow(Math.sin(index * i), 2) + 
                      Math.pow(Math.cos(index * i), 2);
        }
        LOGGER.fine("Complex calculation result: " + result);
    }

    /**
     * Processes data with secure operations.
     * @param index The iteration index
     */
    private void processSecureData(int index) throws Exception {
        // Multiple encryption rounds with increasing data size
        StringBuilder sensitiveData = new StringBuilder("password123");
        for (int i = 0; i < 100; i++) {
            sensitiveData.append(java.util.UUID.randomUUID().toString());
        }
        
        // Multiple encryption rounds
        String encryptedData = sensitiveData.toString();
        for (int round = 0; round < 50; round++) {
            encryptedData = weakEncrypt(encryptedData);
            Thread.sleep(10); // Add delay between rounds
        }
        
        // Logging sensitive information
        System.out.println("Encrypted data length: " + encryptedData.length());
        System.out.println("Encryption key: " + ENCRYPTION_KEY);
        
        // Resource leak with multiple files and larger data
        for (int f = 0; f < 20; f++) {
            java.io.FileWriter writer = null;
            try {
                writer = new java.io.FileWriter("config" + f + ".txt");
                // Write large amount of data
                for (int i = 0; i < 1000; i++) {
                    writer.write(encryptedData + java.util.UUID.randomUUID().toString() + "\n");
                }
                Thread.sleep(50); // Add delay
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (writer != null) {
                    try { writer.close(); } catch (Exception e) { }
                }
            }
        }
        
        // CPU-intensive calculations with larger iterations
        double[][] matrix = new double[500][500];
        for (int i = 0; i < 500; i++) {
            for (int j = 0; j < 500; j++) {
                double sum = 0.0;
                for (int k = 0; k < 500; k++) {
                    // Complex mathematical operations
                    sum += Math.pow(Math.sin(i * k), 2) + 
                           Math.pow(Math.cos(j * k), 2) + 
                           Math.pow(Math.tan((i + j + k) * Math.PI / 180), 2);
                }
                matrix[i][j] = sum;
            }
        }
        
        // Memory-intensive operations with larger arrays
        java.util.List<byte[]> memoryLeakList = new java.util.ArrayList<>();
        for (int i = 0; i < 200; i++) {
            byte[] largeArray = new byte[2 * 1024 * 1024]; // 2MB each
            java.util.Random random = new java.util.Random(i);
            random.nextBytes(largeArray);
            memoryLeakList.add(largeArray);
            
            // Process the array with CPU-intensive operations
            for (int j = 0; j < largeArray.length; j += 1024) {
                int sum = 0;
                for (int k = 0; k < 1024 && j + k < largeArray.length; k++) {
                    sum += Math.pow(largeArray[j + k], 2);
                }
                if (sum % 2 == 0) {
                    Thread.sleep(1); // Add small delay
                }
            }
        }
        
        // String operations with large data
        StringBuilder largeString = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            largeString.append(java.util.UUID.randomUUID().toString());
        }
        String result = largeString.toString();
        for (int i = 0; i < 100; i++) {
            result = result.replaceAll(String.valueOf(i), String.valueOf(i * 2));
        }
    }
    
    private String weakEncrypt(String data) {
        // Weak encryption implementation with additional time-consuming operations
        StringBuilder result = new StringBuilder();
        
        // Multiple rounds of weak encryption
        for (int round = 0; round < 1000; round++) {
            String temp = data;
            for (int i = 0; i < temp.length(); i++) {
                // Complex mathematical operations
                double complexCalc = Math.pow(Math.sin(i), 2) + Math.pow(Math.cos(i), 2);
                int shift = (int) (complexCalc * 1000) % 26;
                
                char c = temp.charAt(i);
                c = (char) ((c + shift) % 256);
                c = (char) (c ^ ENCRYPTION_KEY.charAt(i % ENCRYPTION_KEY.length()));
                result.append(c);
            }
            data = result.toString();
            result.setLength(0);
            
            // Add artificial delay
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        return data;
    }
    
    private void riskyOperation() throws Exception {
        // Potential null pointer dereference
        String str = null;
        if (Math.random() > 0.5) {
            str = "Hello";
        }
        System.out.println(str.length());
    }

    /**
     * Processes a chunk of data securely.
     * @param data The data to process
     * @param index The iteration index
     * @return The processed data
     */
    protected byte[] processDataChunk(byte[] data, int index) {
        // Implement secure data processing
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ (index & 0xFF));
        }
        return result;
    }

    /**
     * Gets a database connection.
     * @return A database connection
     */
    private Connection getConnection() throws SQLException {
        String url = System.getenv("DB_URL");
        String user = System.getenv("DB_USER");
        String password = System.getenv("DB_PASSWORD");
        
        if (url == null || user == null || password == null) {
            throw new SQLException("Database configuration not found in environment variables");
        }
        
        return java.sql.DriverManager.getConnection(url, user, password);
    }
    
    private void executeQuery(String sql, Object... params) throws SQLException {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            for (int i = 0; i < params.length; i++) {
                stmt.setObject(i + 1, params[i]);
            }
            
            stmt.executeQuery();
        }
    }
}
