import java.io.Console;
import java.util.Arrays;

public class test
{
    public static void main(String[] args)
    {
        Console console = System.console();

        System.out.println("Please enter in the master password");
        char[] password = console.readPassword();

        //Copy all of the bytes of characters into the byte array, act as a converter
        byte[] byteArrayOfPassword = new byte[password.length];
        for (int j = 0; j < byteArrayOfPassword.length; j++)
        {
            byteArrayOfPassword[j] = (byte) password[j];
        }


        System.out.println(Arrays.toString(password));
        System.out.println(Arrays.toString(byteArrayOfPassword));

        for (int j = 0; j < byteArrayOfPassword.length; j++)
        {
            password[j] = (char) byteArrayOfPassword[j];
        }

        System.out.println(Arrays.toString(password));
        System.out.println(Arrays.toString(byteArrayOfPassword));
    }
}
