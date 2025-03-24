import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;

public class InsecureSample extends HttpServlet {

    private static final String PASSWORD = "hardcoded123"; // Hardcoded credential
    private static final String DB_URL = "jdbc:mysql://localhost:3306/test";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "root";

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");

        // SQL Injection
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(query);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Command Injection
        try {
            Runtime.getRuntime().exec("ping " + userInput);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // XSS
        response.getWriter().println("<html><body>User Input: " + userInput + "</body></html>");

        // Insecure hashing
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(userInput.getBytes());
            byte[] digest = md5.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Open file without closing
        FileInputStream fis = new FileInputStream(new File("test.txt"));

        // Unsafe deserialization
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("object.ser"));
            Object obj = ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Logging sensitive data
        System.out.println("User password: " + PASSWORD);

        // Unused variable
        int x = 123;

        // Deprecated API usage
        Date date = new Date(2020, 12, 31);

        // Too many nested blocks
        if (true) { if (true) { if (true) { if (true) { if (true) {
            System.out.println("Deep nesting");
        }}}}}

        // Empty catch blocks
        try {
            int a = 1 / 0;
        } catch (Exception e) {}

        // Long method (poor maintainability)
        longMethodWithCodeSmells();
    }

    private void longMethodWithCodeSmells() {
        for (int i = 0; i < 100; i++) {
            System.out.println("Line " + i);
        }

        // 50 duplicate blocks to trigger duplication issues
        for (int i = 0; i < 50; i++) {
            System.out.println("Duplicate block " + i);
        }
        for (int i = 0; i < 50; i++) {
            System.out.println("Duplicate block " + i);
        }
        for (int i = 0; i < 50; i++) {
            System.out.println("Duplicate block " + i);
        }
        for (int i = 0; i < 50; i++) {
            System.out.println("Duplicate block " + i);
        }
    }
}
