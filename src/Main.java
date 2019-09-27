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
import java.util.*;

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
    private static File fileForPassword = new File(filePathForPassword);
    private static File fileForAccounts = new File(filePathForAccounts);

    private static ArrayList<String[]> accounts = new ArrayList<>();

    private static SecretKey aesKey;
    private static IvParameterSpec iv;
    private static Cipher decryptionCipher;
    private static Cipher encryptionCipher;

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

    private static String decryptAndDecode(byte[] byteArrayOfMessage)
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

    private static void createAccountsFile()
    {
        try
        {
            Files.write(Paths.get(filePathForAccounts), encryptAndEncodeMessage(""));
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

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

    private static void readAccountsFromFile()
    {
        String contents;

        try
        {
            contents = decryptAndDecode(Files.readAllBytes(Paths.get(filePathForAccounts)));

            populateArrayFromStringHelper(contents);
        } catch (NoSuchFileException e)
        {
            System.out.println("File not found exception when trying to fill the accounts array.");
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        emptyFile();
    }

    private static void populateArrayFromStringHelper(String content)
    {
        //Fill array list with all of the information from the file.
        int indexOfAccounts = 0;

        for (int i = 0; i < content.length(); i++)
        {
            int indexBetweenAccountAndUsername = content.indexOf(' ', i);
            int indexBetweenUsernameAndPassword = content.indexOf(' ', indexBetweenAccountAndUsername + 1);
            int indexAtEndOfPassword = content.indexOf('\n', indexBetweenUsernameAndPassword);

            accounts.add(indexOfAccounts, new String[]{content.substring(i, indexBetweenAccountAndUsername), content.substring(indexBetweenAccountAndUsername + 1, indexBetweenUsernameAndPassword), content.substring(indexBetweenUsernameAndPassword + 1, indexAtEndOfPassword)});

            indexOfAccounts++;
            i = indexAtEndOfPassword;
        }
    }

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

    private static void saveAccountsToFile()
    {
        try
        {
            PrintWriter out = new PrintWriter(new FileWriter(fileForAccounts, false));

            StringBuilder fullListOfAccounts = new StringBuilder();

            //Write string array, with spaces between them.
            for (String[] account : accounts)
            {
                fullListOfAccounts.append(account[ACCOUNT]).append(" ").append(account[USERNAME]).append(" ").append(account[PASSWORD]);
                fullListOfAccounts.append("\n");
            }

            Files.write(Paths.get(filePathForAccounts), encryptAndEncodeMessage(fullListOfAccounts.toString()));

            out.close();
        } catch (FileNotFoundException e)
        {
            System.out.println("File not found in save to file function. This is a problem, because it should have already been read from.");
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    private static String generateRandomPass(int lengthOfPassword)
    {
        //Create an array of Random Bytes, with length 256.
        //The length of 256 is arbitrary, but its an easy round number so why not.
        byte[] arrayOfRandomBytes = new byte[256];
        new Random().nextBytes(arrayOfRandomBytes);

        StringBuilder stringOfRandomCharacters = new StringBuilder();

        //For loop to walk through the array of random bytes.
        //This loop is broken using a break statement, as i should never actually hit the end of the array,
        //However this is the easiest way to handle an index so this is staying.
        for (int i = 0; i < arrayOfRandomBytes.length; i++)
        {
            //For now we should only accept the character into a string if the character is an accepted character.
            //This includes numbers 0-9, lower case and upper case alphabet. No special characters.

            //If the random byte is a positive integer, then continue testing the number.
            if (arrayOfRandomBytes[i] > 0)
            {
                //Use regex to check if the byte value casts to an accepted value.
                //First cast the byte to a character using the ascii value of the character,
                // then create a string out of the character and test the string using regex
                if (String.valueOf((char) arrayOfRandomBytes[i]).matches("[0-9a-zA-Z]"))
                {
                    //If the character is accepted, append it to the string.
                    stringOfRandomCharacters.append((char) arrayOfRandomBytes[i]);
                }
            }

            //These are our checks to see if we are done.
            //Since not every character is going to be accepted, we can't just look at the step of the for loop.
            //Instead we have to wait until there are actually enough characters in the string
            //Once this happens, break out of the loop.
            if (stringOfRandomCharacters.length() == lengthOfPassword)
            {
                break;
            }

            //Because we are using a random array of bytes and not every character will be accepted, this algorithm has a theoretical running time
            //of infinity. In practice this likely won't happen, but it is possible that we could run out of bytes in the array before we have enough characters.
            //If this ever happens because we get unlucky and none of the bytes are acceptable, scramble the array again, and start the for loop over.
            if (i == arrayOfRandomBytes.length - 1)
            {
                i = 0;
                new Random().nextBytes(arrayOfRandomBytes);
            }
        }

        return stringOfRandomCharacters.toString();
    }

    private static void emptyFile()
    {
        try
        {
            PrintWriter writer = new PrintWriter(fileForAccounts);
            writer.print("");
            writer.close();
        } catch (FileNotFoundException e)
        {
            System.out.println("File not found exception. This shouldn't happen");
            e.printStackTrace();
        }
    }

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
            }
            else
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
        }
        else
        {
            System.out.println("Enter new Master Password.");
            updateMasterPassword(input.next());
            System.out.println("New Master Password saved.");
        }
    }

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

    private static void retrieveAllAccountsFromArray()
    {
        for (int i = 0; i < accounts.size(); i++)
        {
            printAccountInfo(i);
        }
    }

    private static void printAccountInfo(int accountIndex)
    {
        System.out.println("Account name: " + accounts.get(accountIndex)[ACCOUNT]);
        System.out.println("     Account Username: " + accounts.get(accountIndex)[USERNAME]);
        System.out.println("     Account Password: " + accounts.get(accountIndex)[PASSWORD]);
        System.out.println();
    }

    private static String[] getAccount(int accountIndex)
    {
        return accounts.get(accountIndex);
    }

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
        }
        else
        {
            System.out.println("Generating a new password");
            newAccountInformation[PASSWORD] = generateRandomPass(10);
            System.out.println("Finished generating");
        }

        accounts.add(newAccountInformation);

        accounts.sort(Comparator.comparing(o -> o[0]));

        saveAccountsToFile();
    }

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
