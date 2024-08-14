package com.example;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class App2 extends HttpServlet {

    private static final Logger logger = Logger.getLogger(App.class.getName());
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = "root";
    private static final String PASS = "password";
    private static final String AES_KEY = "MySecretKey12345"; // Weak key

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("param");
        String data = fetchData(param);
        response.getWriter().println(data);
    }

    // Vulnerable SQL query with potential SQL Injection
    private String fetchData(String userInput) {
        String result = "";
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                result += "User: " + rs.getString("username") + "<br>";
            }
            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "SQL error", e);
            // Poor error handling
            result = "Error occurred: " + e.getMessage();
        } finally {
            // Potential resource leak
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException se) {
                logger.log(Level.WARNING, "Resource closing failed", se);
            }
        }
        return result;
    }

    // Vulnerable to XSS attacks
    private void sendResponse(HttpServletResponse response, String data) throws IOException {
        response.setContentType("text/html");
        response.getWriter().println("<html><body>" + data + "</body></html>");
    }

    // Weak encryption
    public String encrypt(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return new String(encrypted);
    }

    // Unreachable code
    private int calculate(int a, int b) {
        if (a > 0 && b > 0) {
            return a + b;
        }
        return a - b;
        System.out.println("This will never print"); // Unreachable
    }

    // Inefficient loop
    private List<String> generateList(int n) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < i; j++) {
                list.add("Number: " + j);
            }
        }
        return list;
    }

    // XML parsing without validation
    public Document parseXml(String xmlData) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(xmlData);
        } catch (ParserConfigurationException | SAXException | IOException e) {
            logger.log(Level.SEVERE, "XML Parsing failed", e);
            return null;
        }
    }

    // Concurrency issue
    private int counter = 0;

    public void incrementCounter() {
        counter++;
    }
}
