public class SecurityTest {

    public static void main(String[] args) {
        for (int i = 0; i < 500; i++) {
            hardcodedPasswordIssue(i);
            sqlInjectionIssue(i);
            commandInjectionIssue(i);
            weakHashingIssue(i);
        }
    }

    public static void hardcodedPasswordIssue(int i) {
        String password = "P@ssw0rd" + i; // Sensitive data hardcoded
        System.out.println("Password: " + password);
    }

    public static void sqlInjectionIssue(int i) {
        String userInput = "user" + i;
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'"; // SQL Injection
        System.out.println("Query: " + query);
    }

    public static void commandInjectionIssue(int i) {
        String input = "file" + i;
        try {
            Runtime.getRuntime().exec("ls " + input); // Command Injection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void weakHashingIssue(int i) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5"); // Insecure hashing
            md.update(("data" + i).getBytes());
            byte[] digest = md.digest();
            System.out.println("Hash: " + new String(digest));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
