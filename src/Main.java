import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

//Members: Alex Hover Courtney Kaminski, Pavan Patel

public class Main
{
    private static final String defaultPassword = "";
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
     * Salt and hash the password here
     *
     * @param base64EncodedPassword Base64 encoded version of the password
     * @return The final result of salting and hashing the password.
     */
    //TODO Make this.
    //What is the salt supposed to be?
    public static byte[] saltAndHashPassword(byte[] base64EncodedPassword)
    {
        return null;
    }

    /**
     * Create a file that will contain the password. The password saved should be encrypted and encoded so you can't just open the file to see what the password is.
     * This should ONLY be run if the file does not yet exist, as it will overwrite the existing file, resetting the password to the default.
     * If this is run, it will invalidate all of the existing accounts in the file, because of that, it will remove the accounts file
     * <p>
     * To determine what the password is, it must securely prompt the user to input the password
     */
    //TODO Add the masked input thing into this
    //By default the default password is blank, and the user MUST change this before entering in new accounts, so this should be fine
    private static void createPasswordFile()
    {
        try
        {
            byte[] password = Base64.getEncoder().encode("PASSWORD".getBytes());

            Files.write(Paths.get(filePathForPassword), saltAndHashPassword(password));

            Files.delete(Paths.get(filePathForAccounts));
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Encrypt and encode a given message. This will use the already initialized ciphers to encrypt the message.
     *
     * @param message The string that should be encrypted. The format should be 'salt:Username Password' where the salt is the account name.
     * @return byte[] after the message was encrypted and then encoded using Base64 standard. This is only the cipher text
     */
    //TODO Password based encryption
    private static byte[] encryptAndEncodeAccountInformation(String message)
    {
        byte[] encryptedAndEncoded = new byte[0];
        try
        {
            //message is already formatted in the salted and correct way. All we need is the password based encryption

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
     * @return The string that was contained fully in the cipher. Should be returned in format 'account:username password'
     */
    //TODO Password based encryption
    private static String decryptAndDecodeAccounts(String message)
    {
        try
        {
            //Break apart the message into the different parts
            String messageToBeDecrypted = message.substring(message.indexOf(':') + 1);

            byte[] decodedMessageToBeDecrypted = Base64.getDecoder().decode(messageToBeDecrypted.getBytes());

            //TODO Decrypt it correctly - Password based encryption
            String decryptedInformation = Arrays.toString(decryptionCipher.doFinal(decodedMessageToBeDecrypted));

            //Should be
            return decryptedInformation;

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
            System.out.println("No account file exists, an empty one is being created for you");
            Files.write(Paths.get(filePathForAccounts), Base64.getEncoder().encode("".getBytes()));
        } catch (IOException e)
        {
            System.out.println("Unexpected error occurred");
        }
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
    private static boolean confirmPassword() throws FileNotFoundException
    {
        try
        {
            //If the password file is not found, then it will throw an error back.
            //This should only be thrown if this is called by the "logInAtProgramLaunch" as it should be impossible to pass that method without the file existing
            BufferedReader reader = new BufferedReader(new FileReader(filePathForPassword));
            byte[] hashedVersionOfSavedPasswordOnFile = Base64.getEncoder().encode(reader.readLine().getBytes());

            byte[] enteredPassword = Base64.getEncoder().encode("PASSWORD".getBytes());

            if (Arrays.equals(enteredPassword, hashedVersionOfSavedPasswordOnFile))
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
            if (confirmPassword())
            {
                try
                {
                    BufferedReader accountsFile = new BufferedReader(new FileReader(filePathForAccounts));

                    String line;
                    while ((line = accountsFile.readLine()) != null)
                    {
                        if (line.contains(accountWeAreLookingFor))
                        {
                            return decryptAndDecodeAccounts(line);
                        }
                    }
                } catch (FileNotFoundException e) //Not find account file
                {
                    createAccountsFile();
                } catch (IOException e)
                {
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
     * Print out all of the information about all of the accounts.
     */
    //TODO Account information from file
    private static String retrieveAllAccountsFromArray()
    {
        for (int i = 0; i < accounts.size(); i++)
        {
            printAccountInfo(i);
        }
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
            if (confirmPassword())
            {
                try
                {
                    BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForAccounts, true));

                    writer.write(account + ":" + Arrays.toString(encryptAndEncodeAccountInformation(account + ":" + username + " " + password)));
                } catch (FileNotFoundException e) //Not find account file
                {
                    createAccountsFile();
                    saveNewAccountToFile(account, username, password);
                } catch (IOException e)
                {
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
    private static void logInAtProgramLaunch()
    {
        try
        {
            confirmPassword();

        } catch (FileNotFoundException e) //Password file not found
        {
            System.out.println("You must set a password");
            createPasswordFile();
        }
    }

    /**
     * Allow the master password to be changed securely
     * This is run if there already exists a password, and there may exist accounts on the file using that password to encrypt them.
     * If there already are accounts saved, then it will need to update and change all of those accounts to be saved with the new passwords
     */
    //TODO Password based encryption,
    // will need to interact with accounts file if password changes
    //TODO Mask the user input
    private static void changeMasterPassword()
    {
        System.out.println("Enter in the old password");

        //TODO mask input for old password
        byte[] oldPassword = defaultPassword.getBytes();

        //Check the old password to see if it matches.
        try
        {
            if (!Arrays.equals(oldPassword, Files.readString(Paths.get(filePathForPassword)).getBytes()))
            {
                System.out.println("password does not match");
            }
            //Password does not match so do something about that

        } catch (IOException e)
        {
            e.printStackTrace();
        }


        System.out.println("Enter new Master Password.");

        //Allow the password to be entered in while masked
        //for now, im going to use just the default. This needs changed
        byte[] inputPassword = defaultPassword.getBytes();

        System.out.println("Reenter password to confirm");

        //TODO new password entry that is masked

        //check if the input password matches.
        if (!Arrays.equals(inputPassword, defaultPassword.getBytes()))
        {
            System.out.println("Passwords do not match");
            changeMasterPassword();
        }

        byte[] hashedVersionOfPassword = saltAndHashPassword(inputPassword);

        //Save hashed version to file. Try this first in case there is an error and we can't continue. That way information is not lost in the accounts
        try
        {
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePathForPassword));
            writer.write(Arrays.toString(hashedVersionOfPassword));

            //Update all accounts with the new password.
            updateAllAccountsForNewPassword(inputPassword, oldPassword);
        } catch (FileNotFoundException e) //Password file not found, at this point in the life cycle, this should not happen
        {
            createPasswordFile();
        } catch (IOException e)
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
                //TODO read in all the accounts, decrypt them, and then re-encrypt them
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
        }
        else
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
                    retrieveAllAccountsFromArray();
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
                //Exit
                default:
                    return;
            }
        }
    }

    // Initialize and launch program
    public static void main(String[] args)
    {
        initPrivateKeyAndIV();

        logInAtProgramLaunch();

        mainLoop();
    }
}
