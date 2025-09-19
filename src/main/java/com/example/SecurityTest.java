package com.example;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;

public class SecurityTest {
    public static void main(String[] args) {
        String password = "hardcodedPassword123"; // S2068
        System.out.println("Password: " + password);

        // SQL Injection
        String userInput = "admin' OR '1'='1";
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'"; // S2077
        System.out.println("Query: " + query);

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "root");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("Found user: " + rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Command Injection
        try {
            Runtime.getRuntime().exec("rm -rf /tmp/" + userInput); // S2092
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Insecure Hash
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // S2070
            md.update(password.getBytes());
            byte[] digest = md.digest();
            System.out.println(new String(digest));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
