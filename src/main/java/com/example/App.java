package com.example;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.util.Base64;
import java.util.logging.*;
import javax.servlet.http.*;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class App {

    private static final Logger logger = Logger.getLogger(App.class.getName());

    public static void main(String[] args) {
        // SQL Injection Vulnerability
        sqlInjectionVulnerability("1 OR 1=1");

        // Command Injection Vulnerability
        commandInjectionVulnerability("example.com");

        // Cross-Site Scripting (XSS) Vulnerability
        xssVulnerability("<script>alert('XSS')</script>");

        // Insecure Deserialization Vulnerability
        insecureDeserializationVulnerability();

        // Hardcoded Credentials Vulnerability
        hardcodedCredentialsVulnerability();

        // Insecure Cryptographic Storage Vulnerability
        insecureCryptographicStorageVulnerability("Sensitive Data");

        // Path Traversal Vulnerability
        pathTraversalVulnerability("../../etc/passwd");

        // Trust Boundary Violation
        trustBoundaryViolationVulnerability("user.dir");

        // Open Redirect Vulnerability
        openRedirectVulnerability("http://malicious.com");

        // XML External Entity (XXE) Vulnerability
        xxeVulnerability();

        // Use of Weak Hashing Algorithm
        weakHashingVulnerability("password123");

        // LDAP Injection Vulnerability
        ldapInjectionVulnerability("(|(uid=admin)(uid=*))");

        // Insufficient Logging & Monitoring
        insufficientLoggingVulnerability("Sensitive operation performed.");

        // Clear Text Transmission of Sensitive Information
        clearTextTransmissionVulnerability();
    }

    // SQL Injection Vulnerability
    public static void sqlInjectionVulnerability(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
             Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("User ID: " + rs.getString("id"));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "SQL Injection vulnerability triggered", e);
        }
    }

    // Command Injection Vulnerability
    public static void commandInjectionVulnerability(String host) {
        String command = "ping -c 4 " + host;
        try {
            Process process = Runtime.getRuntime().exec(command);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Command Injection vulnerability triggered", e);
        }
    }

    // Cross-Site Scripting (XSS) Vulnerability
    public static void xssVulnerability(String userInput) {
        String response = "<html><body>User Input: " + userInput + "</body></html>";
        System.out.println(response);
    }

    // Insecure Deserialization Vulnerability
    public static void insecureDeserializationVulnerability() {
        String serializedObject = "rO0ABXNyACxqYXZhLnV0aWwuQXJyYXlMaXN0xwzHcTdc...";
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(serializedObject)))) {
            Object obj = ois.readObject();
            System.out.println("Deserialized Object: " + obj);
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Insecure Deserialization vulnerability triggered", e);
        }
    }

    // Hardcoded Credentials Vulnerability
    public static void hardcodedCredentialsVulnerability() {
        String username = "admin";
        String password = "password123";
        System.out.println("Using credentials: " + username + "/" + password);
    }

    // Insecure Cryptographic Storage Vulnerability
    public static void insecureCryptographicStorageVulnerability(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            System.out.println("MD5 Digest: " + Base64.getEncoder().encodeToString(digest));
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Insecure Cryptographic Storage vulnerability triggered", e);
        }
    }

    // Path Traversal Vulnerability
    public static void pathTraversalVulnerability(String filePath) {
        File file = new File(filePath);
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Path Traversal vulnerability triggered", e);
        }
    }

    // Trust Boundary Violation Vulnerability
    public static void trustBoundaryViolationVulnerability(String property) {
        String value = System.getProperty(property);
        System.out.println("Property Value: " + value);
    }

    // Open Redirect Vulnerability
    public static void openRedirectVulnerability(String redirectUrl) {
        System.out.println("Redirecting to: " + redirectUrl);
        // Normally you would perform a redirect here, e.g., response.sendRedirect(redirectUrl);
    }

    // XML External Entity (XXE) Vulnerability
    public static void xxeVulnerability() {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>";
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "XXE vulnerability triggered", e);
        }
    }

    // Use of Weak Hashing Algorithm
    public static void weakHashingVulnerability(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
            System.out.println("MD5 Hash: " + Base64.getEncoder().encodeToString(hash));
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Weak Hashing vulnerability triggered", e);
        }
    }

    // LDAP Injection Vulnerability
    public static void ldapInjectionVulnerability(String userInput) {
        String ldapFilter = "(&(objectClass=person)(uid=" + userInput + "))";
        System.out.println("LDAP Filter: " + ldapFilter);
        // Assume we perform a search with the above filter
    }

    // Insufficient Logging & Monitoring
    public static void insufficientLoggingVulnerability(String event) {
        System.out.println("Event occurred: " + event);
    }

    // Clear Text Transmission of Sensitive Information
    public static void clearTextTransmissionVulnerability() {
        try (Socket socket = new Socket("example.com", 80);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            out.println("Sensitive data over HTTP"); // Vulnerable: transmitted in clear text
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Clear Text Transmission vulnerability triggered", e);
        }
    }
}
