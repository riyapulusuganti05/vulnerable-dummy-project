package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Properties;

public class App {

    public static void main(String[] args) {
        // SQL Injection Vulnerability
        String userId = "1' OR '1'='1";
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Unvalidated Input Vulnerability
        String filePath = args.length > 0 ? args[0] : "default.txt";
        File file = new File(filePath);

        try {
            file.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Hardcoded Credentials Vulnerability
        String credentials = "user:password";
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        System.out.println("Encoded credentials: " + encodedCredentials);

        // Command Injection Vulnerability
        String command = "ls -l " + args[0]; // Vulnerable: does not sanitize input
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        // Directory Traversal Vulnerability
        try (BufferedReader br = new BufferedReader(new FileReader("../../etc/passwd"))) { // Vulnerable: reads arbitrary files
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Insecure Randomness Vulnerability
        int randomNum = (int) (Math.random() * 100); // Vulnerable: uses insecure randomness
        System.out.println("Random number: " + randomNum);

        // Insecure Network Connection Vulnerability
        try (Socket socket = new Socket("example.com", 80);
             OutputStream out = socket.getOutputStream();
             InputStream in = socket.getInputStream()) {

            out.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes()); // Vulnerable: no SSL/TLS
            int data;
            while ((data = in.read()) != -1) {
                System.out.print((char) data);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Logging Sensitive Information Vulnerability
        Logger logger = Logger.getLogger(App.class.getName());
        logger.log(Level.INFO, "User login attempt with credentials: {0}", credentials); // Vulnerable: logs sensitive info

        // Trust Boundary Violation Vulnerability
        Properties properties = new Properties();
        properties.put("user.dir", args[0]); // Vulnerable: modifies system properties

        try {
            InetAddress.getByName("google.com");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        // Cross-Site Scripting (XSS) Vulnerability
        // Assuming this is a servlet
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("param");
        response.getWriter().write("<html><body>Param: " + param + "</body></html>"); // Vulnerable: reflects untrusted data
    }

    private static final String PASSWORD = "password123"; // Vulnerable: hardcoded sensitive data

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data = request.getReader().readLine();
        response.getWriter().write("<html><body>Data: " + data + "</body></html>"); // Vulnerable: reflects untrusted data
    }

    public void fileDisclosure(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("file");
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) { // Vulnerable: path traversal
            String line;
            while ((line = br.readLine()) != null) {
                response.getWriter().write(line + "<br>");
            }
        } catch (IOException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }
    public void vulnerableSQLInjection(String userInput) {
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'"; // Vulnerable code
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(sql); // Vulnerable code
            while (rs.next()) {
                System.out.println(rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void vulnerableCommandInjection(String userInput) {
        try {
            String command = "ping -c 3 " + userInput; // Vulnerable code
            Process process = Runtime.getRuntime().exec(command); // Vulnerable code
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
    public void vulnerablePathTraversal(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filePath = request.getParameter("file");
        File file = new File("/var/www/uploads/" + filePath); // Vulnerable code

        try (BufferedReader br = new BufferedReader(new FileReader(file))) { // Vulnerable code
            String line;
            while ((line = br.readLine()) != null) {
                response.getWriter().write(line + "<br>");
            }
        } catch (IOException e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }

    import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

    public void vulnerableDeserialization(String serializedObject) {
        try {
            byte[] data = Base64.getDecoder().decode(serializedObject);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)); // Vulnerable code
            Object obj = ois.readObject();
            ois.close();
            System.out.println(obj);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    public void vulnerableIDOR(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("userId");
        String query = "SELECT * FROM users WHERE id = " + userId; // Vulnerable code

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement()) {

            ResultSet rs = stmt.executeQuery(query);
            if (rs.next()) {
                response.getWriter().write("User: " + rs.getString("name"));
            } else {
                response.getWriter().write("User not found");
            }
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
    }


}
