//import javax.crypto.*;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import javax.xml.bind.DatatypeConverter;
//import java.io.UnsupportedEncodingException;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Scanner;
//
//public class Decrypt
//{
//    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
//    {
//        Scanner scanner = new Scanner(System.in);
//
//        System.out.println("Enter base-64 econded ciphertext: ");
//        byte[] ciphertext = DatatypeConverter.parseBase64Binary(scanner.nextLine());
//        System.out.println("Enter base-64 econded IV: ");
//        byte[] iv = DatatypeConverter.parseBase64Binary(scanner.nextLine());
//        System.out.println("Enter base-64 econded secret key: ");
//        byte[] secret_key = DatatypeConverter.parseBase64Binary(scanner.nextLine());
//
//        IvParameterSpec receiver_iv = new IvParameterSpec(iv);
//        SecretKey receiver_secret = new SecretKeySpec(secret_key, "AES");
//
//        Cipher receiver_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        receiver_cipher.init(Cipher.DECRYPT_MODE, receiver_secret, receiver_iv);
//
//        String plaintext = new String(receiver_cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
//
//        System.out.println(plaintext);
//    }
//}
