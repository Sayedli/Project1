import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

/**
 *  Project 1 TCSS 487 With Palo Barreto
 *
 * This class provides a Text-based User Interface (TUI) for Crypto Project 1.
 * It allows users to generate hashes, create authentication tags, encrypt files,
 * and decrypt symmetrically encrypted files with a passphrase.
 * The TUI guides users through the available options and interacts with the user
 * via command-line inputs and outputs.
 *
 * @author Arsh Singh
 * @author Hassan Ali
 */

public class TUI {


    private static final SecureRandom secureRandom = new SecureRandom();

    private static byte[] previousEncrypt;
    private static final String GREETING = "--- Crypto Project 1 ---";
    private static final String MENU = "\nWhat would you like to do?:\n";
    private static final String OUTRO = "Project Exiting.";


    public static void main(String[] args) {
        System.out.println();
        System.out.println(GREETING);
        List<String> options = new ArrayList<>();
        options.add("1. Generate hash from file.");
        options.add("2. Create authentication tag for a file with a passphrase.");
        options.add("3. Encrypt file symmetrically with a passphrase.");
        options.add("4. Decrypt symmetrically encrypted file with a passphrase.");
        options.add("5. Exit");

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println(MENU);
            for (String option : options) {
                System.out.println(option);
            }

            System.out.print("\nEnter your choice:");

            int choice = scanner.nextInt();
            switch (choice) {
                case 1:
                    computeHash(selectMethod(scanner));
                    break;
                case 2:
                    computeAuthTag(selectMethod(scanner));
                    break;
                case 3:
                    encryptFile();
                    break;
                case 4:
                    decryptFile(selectDecryptionMethod(scanner));
                    break;
                case 5:
                    System.out.println(OUTRO);
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid choice. Please try again.");
                    break;
            }
        }
    }

    // Select method for file or text input
    private static String selectMethod(Scanner userInput) {
        String selectionPrompt = "Select an operation:\n" + "1) File\n" + "2) Text input\n";
        int result = getIntegerInRange(userInput, selectionPrompt, 1, 2);
        if (result == 1) {
            return "File";
        } else {
            return "Text";
        }
    }

    // Compute hash based on selected method
    private static void computeHash(String method) {
        byte[] bytes;
        String data = null;
        Scanner userInput = new Scanner(System.in);

        if (method.equals("File")) {
            File file = getFileInput();
            data = readFileToString(file);
        } else if (method.equals("Text")) {
            System.out.println("Enter the text to hash: ");
            data = userInput.nextLine();
        }
        assert data != null;
        bytes = data.getBytes();
        bytes = KMACXOF256.KMACXOF256("".getBytes(), bytes, 512, "D".getBytes());
        System.out.println("Hashed result: " + KMACXOF256.bytesToHexString(bytes));
    }

    // Compute authentication tag based on selected method
    private static void computeAuthTag(String method) {
        byte[] bytes;
        String data = null;
        String passphrase = null;
        Scanner userInput = new Scanner(System.in);

        if (method.equals("File")) {
            File file = getFileInput();
            data = readFileToString(file);
        } else if (method.equals("Text")) {
            System.out.println("Enter the text to hash: ");
            data = userInput.nextLine();
        }

        System.out.println("Enter a passphrase: ");
        passphrase = userInput.nextLine();
        assert data != null;
        bytes = data.getBytes();
        bytes = KMACXOF256.KMACXOF256(passphrase.getBytes(), bytes, 512, "T".getBytes());
        System.out.println("Authentication tag: " + KMACXOF256.bytesToHexString(bytes));
    }

    // Encrypt file with a passphrase
    private static void encryptFile() {
        Scanner input = new Scanner(System.in);
        File file = getFileInput();
        String content = readFileToString(file);
        String passphrase;
        byte[] bytes = content.getBytes();
        System.out.println("Enter a passphrase: ");
        passphrase = input.nextLine();
        previousEncrypt = encryptWithKMAC(bytes, passphrase);
        System.out.println("Encrypted text: " + KMACXOF256.bytesToHexString(previousEncrypt));
    }

    // Read file to string
    public static String readFileToString( File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }

    // Get file input
    public static File getFileInput() {
        String filePath = "tester.txt";

        File theFile = new File(filePath);

        if (theFile.exists()) {
            return theFile;
        } else {
            System.out.println("ERROR: File not found.");
            return null;
        }
    }

    // Encrypt data using KMAC algorithm
    private static byte[] encryptWithKMAC(byte[] m, String pw) {
        byte[] rand = new byte[64];
        secureRandom.nextBytes(rand);

        byte[] keka = KMACXOF256.KMACXOF256(KMACXOF256.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = Arrays.copyOfRange(keka, 0, 64);
        byte[] ka = Arrays.copyOfRange(keka, 64, 128);

        byte[] c = KMACXOF256.KMACXOF256(ke, "".getBytes(), (m.length * 8), "SKE".getBytes());
        c =  KMACXOF256.xorBytes(c, m);
        byte[] t = KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());

        return KMACXOF256.concat(KMACXOF256.concat(rand, c), t);
    }

    // Decrypt file based on selected method
    private static void decryptFile(String method) {
        Scanner input = new Scanner(System.in);
        String passphrase;
        byte[] decryptedBytes = new byte[0];
        System.out.println("Enter the passphrase used for encryption: ");
        passphrase = input.nextLine();
        if (method.equals("Previous")) {
            decryptedBytes = decryptWithKMAC(previousEncrypt, passphrase);
        } else if (method.equals("UserInput")) {
            System.out.println("\nEnter the cryptogram in hex format (one line): \n");
            String cryptogramHex = input.nextLine();
            byte[] hexBytes = KMACXOF256.hexStringToBytes(cryptogramHex);
            decryptedBytes = decryptWithKMAC(hexBytes, passphrase);
        }
        System.out.println("\nDecryption result (Hex format):\n" + KMACXOF256.bytesToHexString(decryptedBytes));
        System.out.println("\nPlain Text:\n" + new String (decryptedBytes, StandardCharsets.UTF_8));
    }

    // Decrypt data using KMAC algorithm
    private static byte[] decryptWithKMAC(byte[] cryptogram, String pw) {
        byte[] rand = new byte[64];

        System.arraycopy(cryptogram, 0, rand, 0, 64);

        byte[] in = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 64);

        byte[] tag = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        byte[] keka = KMACXOF256.KMACXOF256(KMACXOF256.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = KMACXOF256.KMACXOF256(ke, "".getBytes(), (in.length*  8), "SKE".getBytes());
        m = KMACXOF256.xorBytes(m, in);

        byte[] tPrime = KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());

        if (Arrays.equals(tag, tPrime)) {
            return m;
        }
        else {
            throw new IllegalArgumentException("Mismatch on tags");
        }
    }

    // Select decryption method
    private static String selectDecryptionMethod(Scanner userInput) {
        String menu = "Select the decryption method:\n" + "1) Decrypt the previously encrypted text.\n" + "2) Enter the cryptogram manually.\n";
        int input = getIntegerInRange(userInput, menu, 1, 2);
        if (input == 1) {
            return "Previous";
        } else {
            return "UserInput";
        }
    }

    // Get integer within a range from user input
    public static int getIntegerInRange(Scanner userInput, String prompts,
                                        int minMenuInput, int maxMenuInput) {
        int input = getInteger(userInput, prompts);
        while (input < minMenuInput || input > maxMenuInput) {
            System.out.print("Input out of range.\nPlease enter a numerical value from the menu .\n");
            input = getInteger(userInput, prompts);
        }
        return input;
    }

    // Get integer from user input
    public static int getInteger(Scanner userInput, String prompts) {
        System.out.println(prompts);
        while (!userInput.hasNextInt()) {
            userInput.next();
            System.out.println("Invalid input. Please enter an integer.");
            System.out.println(prompts);
        }
        return userInput.nextInt();
    }

}
