package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class App {

    public static void main(String[] args) {
        // SQL Injection Vulnerability
        String userId = "1 OR 1=1";
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
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Cross-Site Scripting (XSS) Vulnerability
        String param = request.getParameter("param");
        response.getWriter().write("<html><body>Param: " + param + "</body></html>");
    }

    private static final String PASSWORD = "secret"; // Hardcoded Credentials Vulnerability
}

