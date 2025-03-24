
public class IssueGenerator {

    public static void main(String[] args) {
        IssueGenerator generator = new IssueGenerator();
        for (int i = 0; i < 100; i++) {
            generator.generateIssues(i);
        }
    }

    public void generateIssues(int index) {
        // Example of hardcoded credentials (S2068)
        String password = "P@ssw0rd123";

        // Unused local variable (code smell)
        int unusedVariable = 42;

        // Too many nested blocks (code smell)
        if (index > 0) {
            if (index < 200) {
                if (index % 2 == 0) {
                    if (index % 3 == 0) {
                        if (index % 5 == 0) {
                            System.out.println("Highly nested code: " + index);
                        }
                    }
                }
            }
        }

        // Empty catch block (S108)
        try {
            int result = 10 / index;
        } catch (Exception e) {
        }

        // SQL injection risk (S2077)
        String userInput = "some_input";
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        executeQuery(sql);

        // Resource not closed (S2095)
        java.io.BufferedReader reader = null;
        try {
            reader = new java.io.BufferedReader(new java.io.FileReader("file.txt"));
            String line = reader.readLine();
        } catch (Exception e) {
        }

        // Hardcoded system property (S2070)
        System.setProperty("java.security.krb5.realm", "EXAMPLE.COM");

        // Logging sensitive data (S2068)
        System.out.println("User password: " + password);

        // Useless method
        doNothing();

        // Duplicated code blocks (code smell)
        for (int i = 0; i < 3; i++) {
            System.out.println("Duplicate block " + i);
            System.out.println("Duplicate block " + i);
            System.out.println("Duplicate block " + i);
        }
    }

    private void executeQuery(String query) {
        // Simulated DB query execution
        System.out.println("Executing query: " + query);
    }

    private void doNothing() {
        // Just a useless method to trigger code smell
    }
}
