import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

//Members: Alex Hover Courtney Kaminski, Pavan Patel

public class Main
{
    private static final String defaultPassword = "";

    private static String filePathForPassword = "Files\\Password.txt";
    private static String filePathForAccounts = "Files\\Accounts.txt";
    private static String filePathForCaCert = "Files\\CaCert.txt";
    private static String filePathForIV = "Files\\IV.dat";
    private static String filePathForKey = "Files\\Key.dat";

    private static SecretKey aesKey;

    private static IvParameterSpec getIv() {
        return iv;
    }

    private static IvParameterSpec iv;
    private static Cipher decryptionCipher;
    private static Cipher encryptionCipher;

    //TODO master password should be salted and hashed.
    //TODO Securely have way to change master password. (PASSWORD BASED ENCRYPTION)
    //TODO Session hijacking - Enter master password to enter new account, search for account, or share account.
    //TODO Have single key to encrypt all usernames and passwords - will be stored in a separate file. Salt encrpyted text with the account, but the entry in the file should be just unencrypted account and cipher text
    //TODO Dont echo typing master password in terminal
    //TODO Ensure sensitive information does not persist in memory. Use base64 encoder to pass around byte arrays
    //TODO Error messages
    //TODO Secure random
    //TODO In order to share a password, you will prompt the user for the name of a certificate for the recipient.  Use a local copy of CACert to verify the certificate, and hybrid encryption to encrypt the password for sending.

    //TODO Use sha to hash that, and finish making the password file, then check the change password method to make sure that makes sense still

    /**
     * A helper function to generate a private key if a private key does not already exist.
     */
    //TODO Password based encryption
    private static void createPrivateKey()
    {
        try
        {
            // Create Key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            aesKey = keygen.generateKey();

            encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);

            iv = new IvParameterSpec(encryptionCipher.getIV());

            decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

            try
            {
                Files.write(Paths.get(filePathForKey), Base64.getEncoder().encode(aesKey.getEncoded()));
                Files.write(Paths.get(filePathForIV), Base64.getEncoder().encode(iv.getIV()));

            } catch (IOException e)
            {
                e.printStackTrace();
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * If a private key already exists, get them from the file system and initialize the ciphers that will be used.
     */
    private static void initPrivateKeyAndIV()
    {
        try
        {
            byte[] ivByteArray = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePathForIV)));
            byte[] keyByteArray = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePathForKey)));

            iv = new IvParameterSpec(ivByteArray);
            aesKey = new SecretKeySpec(keyByteArray, "AES");

            decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

            encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);

        } catch (NoSuchFileException e)
        {
            System.out.println("File not found when trying to fill the IV and Key.");
            System.out.println("Files are being generated");

            createPrivateKey();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Salt and hash the password here
     *
     * @param base64EncodedPassword Base64 encoded version of the password
     * @return The final result of salting and hashing the password.
     */
    private static byte[] saltAndHashPassword(byte[] base64EncodedPassword, int salt)
    {
        //First prepend the password with the salt.
        byte[] saltBytes = Integer.toString(salt).getBytes();
        byte[] saltedPassword = new byte[base64EncodedPassword.length + saltBytes.length];

        for (int i = 0; i < saltedPassword.length; i++)
        {
            if (i < saltBytes.length)
            {
                saltedPassword[i] = saltBytes[i];
            } else
            {
                saltedPassword[i] = base64EncodedPassword[i - saltBytes.length];
            }
        }

        try
        {
            return MessageDigest.getInstance("SHA-256").digest(saltedPassword);
        } catch (NoSuchAlgorithmException e)
        {
            System.out.println("Unexpected error occurred");
        }

        return null;
    }

    /**
     * Create a file that will contain the password. The password saved should be encrypted and encoded so you can't just open the file to see what the password is.
     * This should ONLY be run if the file does not yet exist, as it will overwrite the existing file, resetting the password to the default.
     * If this is run, it will invalidate all of the existing accounts in the file, because of that, it will remove the accounts file
     * <p>
     * To determine what the password is, it must securely prompt the user to input the password
     */
    //By default the default password is blank, and the user MUST change this before entering in new accounts, so this should be fine
    private static void createPasswordFile()
    {
        Console console = System.console();
        Scanner scanner = new Scanner(System.in);

        try
        {
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForPassword, true));

            System.out.println("Please create a master password");
            char[] passwordToSet;

            //Console is null when run from within intellij debugger. Because of this, default to scanner if it doesnt find the console
            if (console == null)
                passwordToSet = scanner.next().toCharArray();
            else
                passwordToSet = console.readPassword();

            //Copy all of the bytes of characters into the byte array, act as a converter
            byte[] byteArrayOfPassword = new byte[passwordToSet.length];
            for (int j = 0; j < byteArrayOfPassword.length; j++)
            {
                byteArrayOfPassword[j] = (byte) passwordToSet[j];
            }

            //Clear contents of password array.
            Arrays.fill(passwordToSet, '0');


            byte[] password = Base64.getEncoder().encode(byteArrayOfPassword);

            int salt = new SecureRandom().nextInt(256);

            writer.write(salt);
            writer.write(saltAndHashPassword(password, salt).toString());

            //Delete the accounts file if it made it this far, because you can't access any of these accounts any more anyway
            Files.delete(Paths.get(filePathForAccounts));
        } catch (NoSuchFileException e)
        {
            System.out.println("     Account file does not exist at this point yet");
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Create an empty file that will contain the accounts information,
     * Should only be called if the file does not yet exist, as it will overwrite the existing file erasing any information in it currently.
     */
    private static void createAccountsFile()
    {
        try
        {
            System.out.println("No account file exists, an empty one is being created for you");
            Files.write(Paths.get(filePathForAccounts), Base64.getEncoder().encode("".getBytes()));
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Encrypt and encode a given message. This will use the already initialized ciphers to encrypt the message.
     *
     * @param message The string that should be encrypted. The format should be 'salt:Username Password' where the salt is the account name.
     * @return byte[] after the message was encrypted and then encoded using Base64 standard. This is only the cipher text
     */
    //TODO Password based encryption
    private static byte[] encryptAndEncodeAccountInformation(String message, byte[] password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] cipherTextBytes = null;

        try {
            final CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(password));
            char[] q = Arrays.copyOf(charBuffer.array(), charBuffer.limit());

            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(q, message.getBytes(), 10000, 256);
            SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
            SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), "AES");

            cipher.init(Cipher.ENCRYPT_MODE, key, getIv());

            cipherTextBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Unexpected error occurred");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Unexpected error occurred");
        } catch (InvalidKeyException e) {
            System.out.println("Unexpected error occurred");
        }
        return cipherTextBytes;
    }

    /**
     * Decode and Decrypt a byte array into a string using the previously initialized ciphers
     *
     * @param message Format is as follows. 'salt:[base64 encoded encryption]'. The salt is in front, followed by a semicolon, and then the message that was encrypted.
     * @return The string that was contained fully in the cipher. Should be returned in format 'account:username password'
     */
    //TODO Password based encryption
    private static String decryptAndDecodeAccounts(String message, byte[] password) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        String decryptedCipherText = null;

        try {
            final CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(password));
            char[] q = Arrays.copyOf(charBuffer.array(), charBuffer.limit());

            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(q, message.getBytes(), 10000, 256);
            SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
            SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), "AES");

            cipher.init(Cipher.DECRYPT_MODE, key, getIv());
            byte[] decryptedCipherTextBytes = cipher.doFinal(Base64.getDecoder().decode(message));

            decryptedCipherText = new String(decryptedCipherTextBytes, StandardCharsets.UTF_8);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Unexpected error occurred");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Unexpected error occurred");
        } catch (InvalidKeyException e) {
            System.out.println("Unexpected error occurred");
        } catch (InvalidKeySpecException e) {
            System.out.println("Unexpected error occurred");
        }
        return decryptedCipherText;
    }

    /**
     * Will compare the password that was passed into the method with the password that is hashed and stored on the file.
     * The method should prompt the user to input the master password, and then should mask the password as it is being typed in
     *
     * @return boolean for if the password matches
     */
    //TODO write this, use the password input thing from console.
    //it needs to hash and check and yeah man
    //If the password is wrong it should loop and ask again. maybe 3 tries before closing program?
    //Right now i have the logic set up in other methods saying that it should only continue if it returns true, but it is technically more secure if it crashes after a few wrong answers.
    //Maybe make it self destruct and delete password file, making the accounts unrecoverable if there are too many guesses, to add to security? - I dont care, just an idea
    //Who ever finishes this, its your call
    //I do know, that because of IO errors it does have to fail closed, not open so be aware of that vulnerability
    private static boolean confirmPassword(byte[] password) throws FileNotFoundException
    {
        BufferedReader reader = new BufferedReader(new FileReader(filePathForPassword));
        try
        {
            //If the password file is not found, then it will throw an error back.
            //This should only be thrown if this is called by the "logInAtProgramLaunch" as it should be impossible to pass that method without the file existing

            //Skip salt line of file.
            int salt = Integer.parseInt(reader.readLine());

            //Pull hash off of the file to compare.
            String hashedVersionOfSavedPasswordOnFile = reader.readLine();


            byte[] passwordToTest = saltAndHashPassword(Base64.getEncoder().encode(password), salt);


            if (passwordToTest.toString().equals(hashedVersionOfSavedPasswordOnFile))
            {
                System.out.println("Password matches, continuing");
                return true;
            }
        } catch (IOException e)
        {
            System.out.println("Unexpected Error");
        }
        return false;
    }

    //TODO After getting this return value make sure this array is cleared.

    /**
     * Prompts user to input a password. This will be matched to the password that is salted and hashed already saved on the file system.
     *
     * @return byte[] of the password that is correct. THIS WILL NEED TO BE CLEARED OUT AFTER USE
     * @throws FileNotFoundException Throws error is password file is removed. At this point, call method to create the password file.
     */
    private static byte[] confirmPassword() throws FileNotFoundException
    {
        Console console = System.console();
        Scanner scanner = new Scanner(System.in);
        for (int i = 0; i < 3; i++)
        {
            if (!Files.exists(Paths.get(filePathForPassword)))
            {
                throw new FileNotFoundException();
            }

            System.out.println("Please enter in the master password");
            char[] password;

            //Console is null when run from within intellij debugger. Because of this, default to scanner if it doesnt find the console
            if (console == null)
                password = scanner.next().toCharArray();
            else
                password = console.readPassword();

            //Copy all of the bytes of characters into the byte array, act as a converter
            byte[] byteArrayOfPassword = new byte[password.length];
            for (int j = 0; j < byteArrayOfPassword.length; j++)
            {
                byteArrayOfPassword[j] = (byte) password[j];
            }

            //Clear contents of password array.
            Arrays.fill(password, '0');

            if (confirmPassword(byteArrayOfPassword))
            {
                return byteArrayOfPassword;
            }
            System.out.println("Not correct");

            Arrays.fill(byteArrayOfPassword, (byte) 0);
        }

        System.out.println("Password not authenticated");
        return null;
    }

    /**
     * Print out all of the information about all of the accounts.
     */
    private static void retrieveAllAccounts()
    {
        try
        {
            BufferedReader reader = new BufferedReader(new FileReader(filePathForAccounts));

            byte[] password = null;

            try
            {
                password = confirmPassword();
            } catch (FileNotFoundException e)
            {
                System.out.println("Unexpected error occurred");
            }

            if (password != null)
            {
                String line;
                while ((line = reader.readLine()) != null)
                {
                    printAccountInfo(decryptAndDecodeAccounts(line, password));
                    System.out.println();
                }
            }
        } catch (FileNotFoundException e)
        {
            System.out.println("Accounts file not found");
            createAccountsFile();
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        } catch (NoSuchPaddingException e) {
            System.out.println("Unexpected error occurred");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Return specific account information. This will prompt user for their password as that will be required as part of the decryption scheme to find the username and password.
     *
     * @param accountWeAreLookingFor The account to find
     * @return A formatted string containing the account information
     */
    private static String returnAccountInfo(String accountWeAreLookingFor)
    {
        try
        {
            byte[] password = confirmPassword();

            if (password != null)
            {
                try
                {
                    BufferedReader accountsFile = new BufferedReader(new FileReader(filePathForAccounts));

                    String line;
                    while ((line = accountsFile.readLine()) != null)
                    {
                        if (line.contains(accountWeAreLookingFor))
                        {
                            return decryptAndDecodeAccounts(line, password);
                        }
                    }
                } catch (FileNotFoundException e) //Not find account file
                {
                    createAccountsFile();
                } catch (IOException e)
                {
                    System.out.println("Unexpected error occurred");
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Unexpected error occurred");
                }
            }
        } catch (FileNotFoundException e) //Error from confirm password, not find password file
        {
            System.out.println("Unexpected error occurred");
        }

        return null;
    }

    /**
     * Save all accounts that are saved in to account arraylist to the file.
     * All of accounts are appended into a long single string, with each account on a seperate line
     * This string is then encrypted+encoded and written to the file.
     *
     * @param account  Name of account to add
     * @param username The username of the account
     * @param password The password of the account
     */
    private static void saveNewAccountToFile(String account, String username, String password)
    {
        try
        {
            byte[] masterPass = confirmPassword();
            if (masterPass != null)
            {
                try
                {
                    BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForAccounts, true));

                    writer.write(account + ":" + Arrays.toString(encryptAndEncodeAccountInformation(account + ":" + username + " " + password, masterPass)));
                } catch (FileNotFoundException e) //Not find account file
                {
                    createAccountsFile();
                    saveNewAccountToFile(account, username, password);
                } catch (IOException e)
                {
                    System.out.println("Unexpected error occurred");
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Unexpected error occurred");
                } catch (InvalidKeySpecException e) {
                    System.out.println("Unexpected error occurred");
                }
            }
        } catch (FileNotFoundException e) //Error from confirm password, not find password file
        {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Generate a secure random string. This random string is
     *
     * @param lengthOfPassword length of password to generate
     * @return The password that was securely generated.
     */
    private static String generateRandomPass(int lengthOfPassword)
    {
        /*
        Create an array of Random Bytes, with length 256.
        The length of 256 is arbitrary, but its an easy round number so why not.
        */
        byte[] arrayOfRandomBytes = new byte[256];
        new SecureRandom().nextBytes(arrayOfRandomBytes);

        StringBuilder stringOfRandomCharacters = new StringBuilder();

        /*
        For loop to walk through the array of random bytes.
        This loop is broken using a break statement, as i should never actually hit the end of the array,
        However this is the easiest way to handle an index so this is staying.
        */
        for (int i = 0; i < arrayOfRandomBytes.length; i++)
        {
            /*
            For now we should only accept the character into a string if the character is an accepted character.
            This includes numbers 0-9, lower case and upper case alphabet, as well as '!' and '.'. No other special characters.

            If the random byte is a positive integer, then continue testing the number.
            Use regex to check if the byte value casts to an accepted value.
            First cast the byte to a character using the ascii value of the character,
             then create a string out of the character and test the string using regex
            */

            if (arrayOfRandomBytes[i] > 0)
            {
                if (String.valueOf((char) arrayOfRandomBytes[i]).matches("[0-9a-zA-Z!.]"))
                {
                    //If the character is accepted, append it to the string.
                    stringOfRandomCharacters.append((char) arrayOfRandomBytes[i]);
                }
            }

            /*
            These are our checks to see if we are done.
            Since not every character is going to be accepted, we can't just look at the step of the for loop.
            Instead we have to wait until there are actually enough characters in the string
            Once this happens, break out of the loop.
            */
            if (stringOfRandomCharacters.length() == lengthOfPassword)
            {
                break;
            }

            /*
            Because we are using a random array of bytes and not every character will be accepted, this algorithm has a theoretical running time
            of infinity. In practice this likely won't happen, but it is possible that we could run out of bytes in the array before we have enough characters.
            If this ever happens because we get unlucky and none of the bytes are acceptable, scramble the array again, and start the for loop over.
            */
            if (i == arrayOfRandomBytes.length - 1)
            {
                i = 0;
                new SecureRandom().nextBytes(arrayOfRandomBytes);
            }
        }

        return stringOfRandomCharacters.toString();
    }

    /**
     * On program launch, this method should initially confirm the password to launch the program
     * If a password does not yet exist, set a password for
     */
    private static boolean logInAtProgramLaunch()
    {
        try
        {
            if (confirmPassword() != null)
            {
                return true;
            }

        } catch (FileNotFoundException e) //Password file not found
        {
            System.out.println("You must set a password");
            createPasswordFile();
            return true;
        }

        return false;
    }

    /**
     * Allow the master password to be changed securely
     * This is run if there already exists a password, and there may exist accounts on the file using that password to encrypt them.
     * If there already are accounts saved, then it will need to update and change all of those accounts to be saved with the new passwords
     */
    private static void changeMasterPassword()
    {
        System.out.println("Enter in the old password");

        Console console = System.console();
        Scanner scanner = new Scanner(System.in);

        char[] oldPasswordCharArray;
        //Console is null when run from within intellij debugger. Because of this, default to scanner if it doesnt find the console
        if (console == null)
            oldPasswordCharArray = scanner.next().toCharArray();
        else
            oldPasswordCharArray = console.readPassword();

        //Copy all of the bytes of characters into the byte array, act as a converter
        //This also will wipe the previous password char array
        byte[] oldPasswordByteArray = new byte[oldPasswordCharArray.length];
        for (int j = 0; j < oldPasswordByteArray.length; j++)
        {
            oldPasswordByteArray[j] = (byte) oldPasswordCharArray[j];
            oldPasswordCharArray[j] = 'p';
        }

        //Check the old password to see if it matches.
        try
        {
            if (!confirmPassword(oldPasswordByteArray))
            {
                System.out.println("Password does not match");
                return;
            }

        } catch (IOException e)
        {
            e.printStackTrace();
        }


        System.out.println("Enter new Master Password.");
        //Allow the password to be entered in while masked
        char[] inputPasswordCharArray1;
        if (console == null)
            inputPasswordCharArray1 = scanner.next().toCharArray();
        else
            inputPasswordCharArray1 = console.readPassword();

        System.out.println("Reenter password to confirm");
        char[] inputPasswordCharArray2;
        if (console == null)
            inputPasswordCharArray2 = scanner.next().toCharArray();
        else
            inputPasswordCharArray2 = console.readPassword();

        if (!Arrays.equals(inputPasswordCharArray1, inputPasswordCharArray2))
        {
            System.out.println("These did not match");
        }

        //Use the new password to continue

        //Copy all of the bytes of characters into the byte array, act as a converter
        //This also will wipe the previous password char array
        byte[] newPasswordByteArray = new byte[oldPasswordCharArray.length];
        for (int j = 0; j < oldPasswordByteArray.length; j++)
        {
            newPasswordByteArray[j] = (byte) inputPasswordCharArray1[j];
            inputPasswordCharArray1[j] = 'p';
            inputPasswordCharArray2[j] = 'p';
        }

        //To use this password, it will need salted.
        int salt = new SecureRandom().nextInt();

        byte[] hashedVersionOfNewPassword = saltAndHashPassword(newPasswordByteArray, salt);

        //Save hashed version to file. Try this first in case there is an error and we can't continue. That way information is not lost in the accounts
        try
        {
            Files.write(Paths.get(filePathForPassword), Base64.getEncoder().encode(Integer.toString(salt).getBytes()));

            BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForPassword, true));
            writer.write('\n' + Arrays.toString(hashedVersionOfNewPassword));

            //Update all accounts with the new password.
            updateAllAccountsForNewPassword(newPasswordByteArray, oldPasswordByteArray);
        } catch (IOException e) //This catch also handles 'FileNotFoundException'. Password file not found, at this point in the life cycle, this should not happen
        {
            System.out.println("Unexpected error occurred");
        }


        System.out.println("New Master Password saved.");
    }

    private static void updateAllAccountsForNewPassword(byte[] inputPassword, byte[] oldPassword)
    {
        String fullListOfEncryptedAccounts = "";
        try
        {
            BufferedReader reader = new BufferedReader(new FileReader(filePathForAccounts));

            String line;
            while ((line = reader.readLine()) != null)
            {
                System.out.println("This is not implemented yet" + line + Arrays.toString(inputPassword) + Arrays.toString(oldPassword));
            }

            //Save the full list of encrypted accounts back onto the file
            Files.write(Paths.get(filePathForAccounts), fullListOfEncryptedAccounts.getBytes());
        } catch (FileNotFoundException e)
        {
            createAccountsFile();
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Print out the information about the actual account. All this does is change the formatting of the string
     *
     * @param accountInfo String of account info, will match the formatting style of 'account:username password' at this point.
     */
    private static void printAccountInfo(String accountInfo)
    {
        if (accountInfo == null)
        {
            return;
        }

        System.out.println("Account name: " + accountInfo.substring(0, accountInfo.indexOf(':')));
        System.out.println("     Account Username: " + accountInfo.substring(accountInfo.indexOf(':') + 1, accountInfo.indexOf(' ')));
        System.out.println("     Account Password: " + accountInfo.substring(accountInfo.indexOf(' ') + 1));
        System.out.println();
    }

    /**
     * Create new account that will be saved in the file.
     */
    private static void storeNewAccount()
    {
        Scanner input = new Scanner(System.in);

        System.out.println("Enter the new account id");
        String account = input.next();

        System.out.println("Enter the new account username");
        String username = input.next();

        System.out.println("Type Y to enter a custom password or N for a random one.");
        String userChoice = input.next();
        String password;

        if (userChoice.equals("Y") || userChoice.equals("y"))
        {
            System.out.println("Enter custom password");
            password = input.next();
        } else
        {
            System.out.println("What length password to generate? Suggested length of 10. Please only enter in an integer above the length of 0.");
            password = generateRandomPass(input.nextInt());
            System.out.println("Generating a new password");
            System.out.println("Finished generating");
        }

        saveNewAccountToFile(account, username, password);
    }

    /**
     * Allow an account to have its information changed.
     */
    private static void updateAccount()
    {
        Scanner input = new Scanner(System.in);

        System.out.println("Please enter in the name of the account you are looking to change. ");
        String nameOfAccount = input.next();

        String fullAccountInfo = returnAccountInfo(nameOfAccount);

        if (fullAccountInfo == null)
        {
            System.out.println("Unable to continue");
            return;
        }

        //Separate out the account information into the pieces
        String account = fullAccountInfo.substring(0, fullAccountInfo.indexOf(':'));
        String username = fullAccountInfo.substring(fullAccountInfo.indexOf(':') + 1, fullAccountInfo.indexOf(' '));
        String password = fullAccountInfo.substring(fullAccountInfo.indexOf(' ') + 1);

        //Print out account information
        System.out.println("Current account name: " + account);
        System.out.println("Current User name: " + username);
        System.out.println("Current Password: " + password);

        System.out.println();

        //Delete current entry for the account
        deleteAccount(account);
        //Create new entry for the updated account
        storeNewAccount();
    }

    /**
     * Allow user to remove account.
     * This method works by opening a temp list, and copying all of the contents of the accounts file into it
     * After that, it will flush the original file, and copy all of the accounts back into the original file except for the one to delete
     *
     * @param accountToRemove Scanner for user input
     */
    private static void deleteAccount(String accountToRemove)
    {
        try
        {
            //First copy all of the contents into a temporary system.
            BufferedReader reader = new BufferedReader(new FileReader(filePathForAccounts));

            ArrayList<String> accounts = new ArrayList<>();

            String line;
            while ((line = reader.readLine()) != null)
            {
                if (!line.substring(line.indexOf(':')).equals(accountToRemove))
                {
                    accounts.add(line);
                }
            }

            Files.write(Paths.get(filePathForAccounts), "".getBytes());

            //Now write all of the lines back into it
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForAccounts, true));
            for (String account : accounts)
            {
                writer.write(account);
            }
        } catch (FileNotFoundException e)
        {
            System.out.println("No account file exists, please enter an account first");
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
    }

    private static void shareAccount(String accountInfo)
    {
        Scanner scanner = new Scanner(System.in);
        boolean check = false;

        try
        {
            //First copy all of the contents into a temporary system.
            BufferedReader certification = new BufferedReader(new FileReader(filePathForCaCert));

            ArrayList<String> accounts = new ArrayList<>();

            String line;
            while ((line = certification.readLine()) != null)
            {
                accounts.add(line);
            }

            if (accountInfo == null)
            {
                return;
            }
            else
            {
                System.out.println("Please enter your Certification.");
                String cert = scanner.nextLine();
                for (int i = 0; i < accounts.size(); i++)
                {
                    if(cert.equals(accounts.get(i)))
                        check = true;
                }
            }

            if(check == false)
            {
                return;
            }


            System.out.println("Account name: " + accountInfo.substring(0, accountInfo.indexOf(':')));
            System.out.println("     Account Username: " + accountInfo.substring(accountInfo.indexOf(':') + 1, accountInfo.indexOf(' ')));
            System.out.println("     Account Password: " + accountInfo.substring(accountInfo.indexOf(' ') + 1));
            System.out.println();

            Files.write(Paths.get(filePathForCaCert), "".getBytes());

            //Now write all of the lines back into it
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForCaCert, true));
            for (String account : accounts)
            {
                writer.write(account);
            }
        } catch (FileNotFoundException e)
        {
            System.out.println("No account file exists, please enter an account first");
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
    }

    /**
     * Main loop that the program exists in. This loops and allows the user many choices to allow the user to interact with the program.
     */
    private static void mainLoop()
    {
        Scanner input = new Scanner(System.in);

        //Program actions
        while (true)
        {
            System.out.println("Would do you want to do? Type 1 to retrieve a single account, \n" + "2 to retrieve a list of all accounts stored, \n" + "3 to store a new account, \n" + "4 to update an account, \n" + "5 to delete an account, \n" + "6 to change master password, \n" + "or anything else to exit.");

            int actions = input.nextInt();
            switch (actions)
            {
                //Retrieve single account
                case 1:
                    System.out.println("Print out a single account");
                    System.out.println("Enter the name of the account to find");
                    printAccountInfo(returnAccountInfo(input.nextLine()));
                    break;
                //Retrieve all accounts
                case 2:
                    System.out.println("Print out all accounts");
                    retrieveAllAccounts();
                    break;
                //Store new account
                case 3:
                    System.out.println("Store new account");
                    storeNewAccount();
                    break;
                //Update or delete accounts
                case 4:
                    System.out.println("Update account");
                    updateAccount();
                    break;
                //Delete Account
                case 5:
                    System.out.println("Delete account");
                    System.out.println("Enter the name of the account to delete");
                    deleteAccount(input.nextLine());
                    break;
                //Change master password
                case 6:
                    System.out.println("Changing master password");
                    changeMasterPassword();
                    break;
                case 7:
                    System.out.println("Sharing Account");
                    shareAccount(returnAccountInfo(input.nextLine()));
                    break;
                //Exit
                default:
                    return;
            }
        }
    }

    // Initialize and launch program
    public static void main(String[] args)
    {
//        initPrivateKeyAndIV();

        if (!logInAtProgramLaunch())
            return;

//        mainLoop();
    }
}
