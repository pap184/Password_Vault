import java.io.*;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

//Members: Alex Hover Courtney Kaminski, Pavan Patel

public class Main
{
    private static File file = new File("Files\\Accounts");

    public static void main(String[] args) throws IOException
    {
        //Scanners
        BufferedReader reader = new BufferedReader(new FileReader(file));
        PrintWriter out = new PrintWriter(new FileWriter(file, true));
        Scanner input = new Scanner(System.in);

        //Variables
        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        String newMasterPass, userPass, actions, line;
        String[] newAccount = new String[3];
        boolean check = false, actionChecker = false;
        ArrayList<String> accounts = new ArrayList<>();

        //Read file to array
        while ((line = reader.readLine()) != null)
        {
            accounts.add(line);
        }
        clear();

        //Program Start
        //Login
        System.out.println("Please enter the Master Password");
        userPass = input.next();
        while (!check)
        {
            if (userPass.equals(accounts.get(0)))
            {
                System.out.println("Enter Y to change the master password or N to not.");
                check = true;
            } else
            {
                System.out.println("Error!");
                System.out.println("Please enter the Master Password.");
                userPass = input.next();
            }
        }

        //Master Password change
        if (input.next().equals("Y"))
        {
            System.out.println("Enter Master Password.");
            newMasterPass = input.next();
            System.out.println("New Master Password saved.");
            accounts.set(0, newMasterPass);
        }

        //Program actions
        while (!actionChecker)
        {
            System.out.println("Would do you want to do? Type 1 to retrieve, 2 to store, or anything else to exit.");
            actions = input.next();
            switch (actions)
            {
                //Retrieve
                case "1":
                    System.out.println("Please enter the id of the account that you want to access");
                    String id = input.next();
                    String account;
                    for (int i = 1; i < accounts.size(); i++)
                    {
                        account = accounts.get(i);
                        if (account.contains(id))
                        {
                            System.out.println(account);
                        }
                    }
                    break;
                //Store
                case "2":
                    System.out.println("Enter the new account id");
                    newAccount[0] = input.next();
                    System.out.println("Enter the new account user");
                    newAccount[1] = input.next();
                    System.out.println("Type Y to enter a custom password or N for a random one.");
                    if (input.next().equals("Y"))
                    {
                        System.out.println("Enter custom password");
                        newAccount[2] = input.next();
                    } else
                    {
                        newAccount[2] = generateRandomPass(characters, 10);
                    }
                    String acc = "id=" + newAccount[0] + " user=" + newAccount[1] + " password=" + newAccount[2];
                    accounts.add(acc);
                    break;
                //Exit
                default:
                    out.append(accounts.get(0));
                    for (int i = 1; i < accounts.size(); i++)
                    {
                        out.append("\n");
                        out.append(accounts.get(i));
                    }
                    out.close();
                    System.out.println("Remember everything is saved on your trusty accounts text file so make sure to send it to all your friends.");
                    System.out.println("Terminate Program");
                    actionChecker = true;
            }
        }
    }

    private static String generateRandomPass(String characters, int i)
    {
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int j = 0; j < i; j++)
        {
            sb.append(characters.charAt(random.nextInt(characters.length())));
        }
        return sb.toString();
    }

    private static void clear() throws IOException
    {
        PrintWriter writer = new PrintWriter(file);
        writer.print("");
        writer.close();
    }
}
