import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

public class Test_CBC {

    public static void main(String[] args) throws Exception {

        byte[] byteKey = new byte[]{(byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54,
                (byte) 55, (byte) 56, (byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52,
                (byte) 53, (byte) 54};

//        byte[] testInput = new byte[]{(byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54,
//                (byte) 55, (byte) 56, (byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52,
//                (byte) 53, (byte)54};

        File archivo = new File("C:/Users/danyk/test0.txt");


        try (FileInputStream fis = new FileInputStream(archivo);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int byteLeido;
            while ((byteLeido = fis.read()) != -1) {
                baos.write(byteLeido);
            }

            byte[] byteArray = baos.toByteArray();
            String text = new String(byteArray);
            SymmetricCipher s =  new SymmetricCipher();
            System.out.println("Text to be processed: \n\t" + text);

            byte[] encrypted = s.encryptCBC(byteArray, byteKey);
            String encryptedText = new String(encrypted);
            System.out.println("Encrypted text: \n\t" + encryptedText);

            byte[] decrypted = s.decryptCBC(encrypted, byteKey);
            String decryptedText = new String(decrypted);
            System.out.println("Decrypted text: \n\t" + decryptedText);

            // Ahora byteArray contiene los bytes del archivo
            System.out.println("Archivo convertido a bytes exitosamente.");
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}
