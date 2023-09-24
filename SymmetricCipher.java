import java.security.InvalidKeyException;
import java.util.Arrays;


public class SymmetricCipher {
    
    // Initialization Vector (fixed)

    byte[] iv = new byte[]{(byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54,
            (byte) 55, (byte) 56, (byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52,
            (byte) 53, (byte) 54};

    /* Constructor method */

    /*************************************************************************************/
    public SymmetricCipher() throws InvalidKeyException {
    }

    /* Method to encrypt using AES/CBC/PKCS5 */

    /*************************************************************************************/
    public byte[] encryptCBC(byte[] input, byte[] byteKey) throws Exception {

        SymmetricEncryption e = new SymmetricEncryption(byteKey);

        // Add the padding

        int padding_length;
        if(input.length % e.AES_BLOCK_SIZE == 0){
            padding_length = e.AES_BLOCK_SIZE;
        } else {
            padding_length = e.AES_BLOCK_SIZE - (input.length % e.AES_BLOCK_SIZE);
        }
        byte[] padding = new byte[padding_length];
        for(int i = 0; i < padding_length; i ++) {
            padding[i] = (byte) padding_length;
        }

        byte[] paddedText = new byte[input.length + padding.length];
        System.arraycopy(input, 0, paddedText, 0, input.length);
        System.arraycopy(padding, 0, paddedText, input.length, padding.length);

        byte[] encryptedText = new byte[paddedText.length];
        byte[] aux = iv;

        // Generate the cipherText

        for(int i = 0; i < paddedText.length/e.AES_BLOCK_SIZE; i ++){
            byte[] inputBlock = new byte[e.AES_BLOCK_SIZE];
            
            System.arraycopy(paddedText, i*e.AES_BLOCK_SIZE, inputBlock, 0, e.AES_BLOCK_SIZE);

            byte [] xorOutputBlock = xorFunction(inputBlock, aux, e.AES_BLOCK_SIZE);
            byte[] encryptedBlock = e.encryptBlock(xorOutputBlock);
            aux = encryptedBlock;
            System.arraycopy(encryptedBlock, 0, encryptedText, i*e.AES_BLOCK_SIZE, e.AES_BLOCK_SIZE);
        }

        return encryptedText;
    }
    


    /* Method to decrypt using AES/CBC/PKCS5 */

    /*************************************************************************************/


    public byte[] decryptCBC(byte[] input, byte[] byteKey) throws Exception {
        
        SymmetricEncryption d = new SymmetricEncryption(byteKey);
                
        byte[] finalPlaintext;
        byte[] paddedText = new byte[input.length];
        byte[] aux = iv;

        // Generate the plaintext
        for(int i = 0; i < input.length/d.AES_BLOCK_SIZE; i++){
            byte[] inputBlock = new byte[d.AES_BLOCK_SIZE];

            System.arraycopy(input, i*d.AES_BLOCK_SIZE, inputBlock, 0, d.AES_BLOCK_SIZE);

            byte[] decryptedInputBlock = d.decryptBlock(inputBlock);
            byte[] xorOutputBlock = xorFunction(decryptedInputBlock, aux, d.AES_BLOCK_SIZE);
            aux = inputBlock;
            System.arraycopy(xorOutputBlock, 0, paddedText, i*d.AES_BLOCK_SIZE, d.AES_BLOCK_SIZE);
        }

        // Eliminate the padding

        int paddingValue = (int) paddedText[paddedText.length - 1];
        if(paddingValue < 1 || paddingValue > d.AES_BLOCK_SIZE){
            throw new IllegalArgumentException("Padding not Valid, text received: \n\t" + Arrays.toString(paddedText));
        }
        finalPlaintext = new byte[paddedText.length - paddingValue];
        System.arraycopy(paddedText, 0, finalPlaintext, 0, finalPlaintext.length);

        return finalPlaintext;
    }

    private byte[] xorFunction (byte[] block1, byte [] block2, int block_size) {
        byte[] xorFinal = new byte[block_size];

        for(int i = 0; i < block_size; i++) {
            byte xor = (byte) (block1[i] ^  block2[i]);
            xorFinal[i] = xor;
        }

        return xorFinal;
    }

}
