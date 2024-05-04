import java.util.Arrays;

public class CryptoTests {
    public static void main(String[] args) {
        testKMACXOF256();
    }

    public static void testKMACXOF256() {
        byte[] key = hexStringToByteArray(R.testData_KMAC.KEY_HEX);
        byte[] data = hexStringToByteArray(R.testData_KMAC.DATA_HEX);
        int outputLength = 256;
        byte[] customString = "".getBytes();

        byte[] expectedOutput = hexStringToByteArray(R.testData_KMAC.OUTVAL_HEX);
        byte[] actualOutput = KMACXOF256.KMACXOF256(key, data, outputLength, customString);

        boolean testPassed = Arrays.equals(actualOutput, expectedOutput);

        if (testPassed) {
            System.out.println("KMACXOF256 Sample #1 Test Passed");
        } else {
            System.out.println("KMACXOF256 Sample #1 Test Failed");
            System.out.println("Expected: " + Arrays.toString(expectedOutput));
            System.out.println("Actual  : " + Arrays.toString(actualOutput));
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        // Remove spaces or other delimiters from hex string
        s = s.replaceAll("\\s", "");

        // Check if the string length is even
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }

        // Validate the string contains only valid hex characters
        if (!s.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Hex string contains invalid characters");
        }

        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}