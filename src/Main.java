import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Comparator;
import java.util.Random;
import java.util.Scanner;

//Members: Alex Hover Courtney Kaminski, Pavan Patel

public class Main
{
    private static final String defaultPassword = "password";
    private static final int ACCOUNT = 0;
    private static final int USERNAME = 1;
    private static final int PASSWORD = 2;

    private static String filePathForPassword = "Files\\Password.dat";
    private static String filePathForAccounts = "Files\\Accounts.dat";
    private static String filePathForIV = "Files\\IV.dat";
    private static String filePathForKey = "Files\\Key.dat";

    private static SecretKey aesKey;
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
     * Encrypt and encode a given message. This will use the already initialized ciphers to encrypt the message.
     *
     * @param message The string that should be encrypted. The format should be 'salt:Username Password' where the salt is the account name.
     * @return Byte[] after the message was encrypted and then encoded using Base64 standard
     */
    //TODO Password based encryption
    private static byte[] encryptAndEncodeMessage(String message)
    {
        byte[] encryptedAndEncoded = new byte[0];
        try
        {
            encryptedAndEncoded = encryptionCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            encryptedAndEncoded = Base64.getEncoder().encode(encryptedAndEncoded);
        } catch (BadPaddingException | IllegalBlockSizeException e)
        {
            e.printStackTrace();
        }

        return encryptedAndEncoded;
    }

    /**
     * Decode and Decrypt a byte array into a string using the previously initialized ciphers
     *
     * @param message Format is as follows. 'salt:[base64 encoded encryption]'. The salt is in front, followed by a semicolon, and then the message that was encrypted.
     * @return The string that was returned by our ciphers
     */
    //TODO Password based encryption
    private static String decryptAndDecodeAccounts(String message)
    {
        try
        {
            byte[] decodedMessage = Base64.getDecoder().decode(byteArrayOfMessage);
            return new String(decryptionCipher.doFinal(decodedMessage), StandardCharsets.UTF_8);

        } catch (BadPaddingException | IllegalBlockSizeException e)
        {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * Create an empty file that will contain the accounts information,
     * Should only be called if the file does not yet exist, as it will overwrite the existing file erasing any information in it currently.
     */
    private static void createAccountsFile()
    {
        try
        {
            Files.write(Paths.get(filePathForAccounts), Base64.getEncoder().encode("".getBytes()));
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Create a file that will contain the password. The password saved should be encrypted and encoded so you can't just open the file to see what the password is.
     * This should only be run if the file does not yet exist, as it will overwrite the existing file, resetting the password to the default.
     *
     * @return String of what the password defaults too, in case it is different.
     */
    //TODO Password should be hashed
    private static String createPasswordFile()
    {
        try
        {
            Files.write(Paths.get(filePathForPassword), encryptAndEncodeMessage(defaultPassword));
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        return defaultPassword;
    }

    /**
     * Will compare the password that was passed into the method with the password that is hashed and stored on the file.
     * @param passwordEntered base64 encoding of the password that was entered.
     * @return boolean for if the password matches
     */
    //TODO write this
    //it needs to hash and check and yeah man
    private static boolean confirmPassword(byte[] passwordEntered)
    {
        return true;
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
            BufferedReader accountsFile = new BufferedReader(new FileReader(filePathForAccounts));

            String line;
            while ((line = accountsFile.readLine()) != null)
            {
                if (line.contains(accountWeAreLookingFor))
                {

                    return line.substring(0, line.indexOf(' ')) + decryptAndDecodeAccounts(line);
                }
            }

        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        return "Account could not be found.";
    }

    /**
     * Return master password that is currently saved.
     *
     * @return String of password that is saved
     */
    //TODO This is really dumb, get rid of this
    private static String pullMasterPassword()
    {
        try
        {
            return decryptAndDecode(Files.readAllBytes(Paths.get(filePathForPassword)));

        } catch (NoSuchFileException e)
        {
            System.out.println("Files not found when trying to pull master password");
            System.out.println("Files are being generated");

            createAccountsFile();
            return createPasswordFile();
        } catch (IOException e)
        {
            System.out.println("Unknown other error");
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Save master password to file.
     *
     * @param masterPassword String that the password should be changed too
     */
    //TODO Password based encryption
    private static void updateMasterPassword(String masterPassword)
    {
        try
        {
            Files.write(Paths.get(filePathForPassword), encryptAndEncodeMessage(masterPassword));

        } catch (FileNotFoundException e)
        {
            System.out.println("File not found in save password to file function. This is a problem, because it should have already been read from.");
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Save all accounts that are saved in to account arraylist to the file.
     * All of accounts are appended into a long single string, with each account on a seperate line
     * This string is then encrypted+encoded and written to the file.
     */
    //TODO Accounts should be kept on the file permanently.
    private static void saveNewAccountToFile(String account, String username, String password)
    {
        try
        {


            Files.write(Paths.get(filePathForAccounts), encryptAndEncodeMessage(fullListOfAccounts.toString()));

        } catch (FileNotFoundException e)
        {
            System.out.println("File not found in save to file function. This is a problem, because it should have already been read from.");
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Generate a secure random string. This random string is
     *
     * @param lengthOfPassword length of password to generate
     * @return The password that was securely generated.
     */
    //TODO Should not be kept in memory
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
                new Random().nextBytes(arrayOfRandomBytes);
            }
        }

        return stringOfRandomCharacters.toString();
    }

    /**
     * Clear account file
     * I dont know why this exists anymore
     */
    //TODO remove this too
    private static void emptyFile()
    {
        try
        {
            Files.write(Paths.get(filePathForAccounts), encryptAndEncodeMessage(""));

        } catch (FileNotFoundException e)
        {
            System.out.println("File not found exception. This shouldn't happen");
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Verify master password is correct
     *
     * @param input scanner that the user will type in the password with
     */
    //TODO Information should not persist in memory
    //TODO This will need to reauthenticate every time
    private static void logIn(Scanner input)
    {
        String masterPassword = pullMasterPassword();

        //Program Start
        //Login
        System.out.println("Please enter the Master Password");
        String userPass = input.next();

        while (true)
        {
            if (userPass.equals(masterPassword))
            {
                break;
            } else
            {
                System.out.println("Error!");
                System.out.println("Please enter the Master Password.");
                userPass = input.next();
            }
        }

        if (masterPassword.equals(defaultPassword))
        {
            System.out.println("This is the default password, and you must change this password.");
            changeMasterPassword(input, true);
        }
    }

    /**
     * Allow the master password to be changed securely
     *
     * @param input        Scanner the user inputs too
     * @param forcedChange If the user has to change it
     */
    //TODO Password based encryption, will need to interact with accounts file if password changes
    private static void changeMasterPassword(Scanner input, boolean forcedChange)
    {
        //Prompt user to change password.
        //The user is required to change the password if the password is the default password

        //Master Password change
        if (!forcedChange)
        {
            System.out.println("Enter Y to change the master password or N to not.");

            if (input.next().equals("Y") || input.next().equals("y"))
            {
                System.out.println("Enter new Master Password.");
                updateMasterPassword(input.next());
                System.out.println("New Master Password saved.");
            }
        } else
        {
            System.out.println("Enter new Master Password.");
            updateMasterPassword(input.next());
            System.out.println("New Master Password saved.");
        }
    }

    /**
     * Find account index in the accounts arraylist
     * @param accountWeAreLookingFor The name of the account searched for
     * @return The index the account exists at
     */
    private static int findAccountIndexFromUserInput(String accountWeAreLookingFor)
    {
        for (int i = 0; i < accounts.size(); i++)
        {
            if (accountWeAreLookingFor.toLowerCase().equals(accounts.get(i)[0].toLowerCase()))
            {
                System.out.println("Account found\n");
                return i;
            }
        }

        System.out.println("Error, account could not be found.");
        return -1;
    }

    /**
     * Pull information about a single account
     *
     * @param input Scanner that the user will type in their account they want
     */
    //TODO Account information persists on file now
    private static void retrieveSingleAccountInfoFromArray(Scanner input)
    {
        System.out.println("Please enter the name of the account that you want to access");
        String accountWeAreLookingFor = input.next();

        int indexOfAccount = findAccountIndexFromUserInput(accountWeAreLookingFor);

        if (!(indexOfAccount < 0))
        {
            printAccountInfo(indexOfAccount);
        }
    }

    /**
     * Print out all of the information about all of the accounts.
     */
    //TODO Account information from file
    private static void retrieveAllAccountsFromArray()
    {
        for (int i = 0; i < accounts.size(); i++)
        {
            printAccountInfo(i);
        }
    }

    /**
     * Print out the information about the actual account.
     *
     * @param accountIndex Index that the account exists at.
     */
    //TODO Account information exists in file system
    private static void printAccountInfo(int accountIndex)
    {
        System.out.println("Account name: " + accounts.get(accountIndex)[ACCOUNT]);
        System.out.println("     Account Username: " + accounts.get(accountIndex)[USERNAME]);
        System.out.println("     Account Password: " + accounts.get(accountIndex)[PASSWORD]);
        System.out.println();
    }

    /**
     * get the specific string[] that contains information about the account
     *
     * @param accountIndex index that the account exists in
     * @return string[] that the account information is in
     */
    //TODO This is dumb too. Get rid of this
    private static String[] getAccount(int accountIndex)
    {
        return accounts.get(accountIndex);
    }

    /**
     * Create new account that will be saved in the file.
     * @param input Scanner the user inputs their choices into
     */
    //TODO Accounts on file
    private static void storeNewAccount(Scanner input)
    {
        String[] newAccountInformation = new String[3];

        System.out.println("Enter the new account id");
        newAccountInformation[ACCOUNT] = input.next();

        System.out.println("Enter the new account username");
        newAccountInformation[USERNAME] = input.next();

        System.out.println("Type Y to enter a custom password or N for a random one.");
        String userChoice = input.next();

        if (userChoice.equals("Y") || userChoice.equals("y"))
        {
            System.out.println("Enter custom password");
            newAccountInformation[PASSWORD] = input.next();
        } else
        {
            System.out.println("Generating a new password");
            newAccountInformation[PASSWORD] = generateRandomPass(10);
            System.out.println("Finished generating");
        }

        accounts.add(newAccountInformation);

        accounts.sort(Comparator.comparing(o -> o[0]));

        saveAccountsToFile();
    }

    /**
     * Allow an account to have its information changed.
     * @param input scanner for user input
     */
    //TODO Accounts on file.
    private static void updateAccount(Scanner input)
    {
        System.out.println("Please enter in the name of the account you are looking for. ");
        String userChoice = input.next();

        int accountIndex = findAccountIndexFromUserInput(userChoice);

        if (!(accountIndex < 0))
        {
            String[] accountInfo = getAccount(accountIndex);

            //Print out account information
            System.out.println("Current account name: " + accountInfo[ACCOUNT]);
            System.out.println("Current User name: " + accountInfo[USERNAME]);
            System.out.println("Current Password: " + accountInfo[PASSWORD]);

            System.out.println();

            System.out.println("Enter a new Account Name: ");
            accountInfo[ACCOUNT] = input.next();
            System.out.println("Enter a new Username: ");
            accountInfo[USERNAME] = input.next();
            System.out.println("Enter a new password: ");
            accountInfo[PASSWORD] = input.next();
        }

        saveAccountsToFile();
    }

    /**
     * Allow user to remove account.
     * @param input Scanner for user input
     */
    //TODO Accounts on file.
    private static void deleteAccount(Scanner input)
    {
        System.out.println("Please enter in the name of the account you are looking for. ");
        String userChoice = input.next();

        int accountIndex = findAccountIndexFromUserInput(userChoice);

        if (!(accountIndex < 0))
        {
            printAccountInfo(accountIndex);

            System.out.println();

            accounts.remove(accountIndex);

            System.out.println("Account Deleted.");
        }

        saveAccountsToFile();
    }

    /**
     * Main loop that the program exists in. This loops and allows the user many choices to allow the user to interact with the program.
     * @param input scanner for user input
     */
    private static void mainLoop(Scanner input)
    {
        //Program actions
        while (true)
        {
            System.out.println("Would do you want to do? Type 1 to retrieve a single account, \n" + "2 to retrieve a list of all accounts stored, \n" + "3 to store a new account, \n" + "4 to update an account, \n" + "5 to delete an account, \n" + "6 to change master password, \n" + "or anything else to exit.");

            String actions = input.next();
            switch (actions)
            {
                //Retrieve single account
                case "1":
                    System.out.println("Print out a single account");
                    retrieveSingleAccountInfoFromArray(input);
                    break;
                //Retrieve all accounts
                case "2":
                    System.out.println("Print out all accounts");
                    retrieveAllAccountsFromArray();
                    break;
                //Store new account
                case "3":
                    System.out.println("Store new account");
                    storeNewAccount(input);
                    break;
                //Update or delete accounts
                case "4":
                    System.out.println("Update an account");
                    updateAccount(input);
                    break;
                //Delete Account
                case "5":
                    System.out.println("Delete an account");
                    deleteAccount(input);
                    break;
                //Change master password
                case "6":
                    System.out.println("Changing master password");
                    changeMasterPassword(input, false);
                    break;
                //Exit
                default:
                    return;
            }

            saveAccountsToFile();
        }
    }

    // Initialize and launch program
    public static void main(String[] args)
    {
        //Scanner used to parse user input
        Scanner input = new Scanner(System.in);

        initPrivateKeyAndIV();

        logIn(input);

        readAccountsFromFile();

        mainLoop(input);
    }
}
