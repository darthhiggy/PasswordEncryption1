package com.company;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.Scanner;

public class Main
{
    private static int ITERATIONS = 1000;

    private static void usage()
    {
        System.err.println("Usage: java PBE-e|-d password text");
        System.exit(1);
    }
    public static void main(String[] args) throws Exception
    {
        try
        {
            Scanner scan = new Scanner(System.in);
            System.out.println("Enter a password: ");
            String password = scan.nextLine();
            System.out.println("Enter String to be encrypted: ");
            String text = scan.nextLine();
            String encryptedText = encrypt(password, text);
            System.out.println(encryptedText);

            System.out.println("Enter a password: ");
            password = scan.nextLine();

            System.out.println(decrypt(password, encryptedText));
        }

        catch(Exception e)
        {
            System.out.println("Invalid Password!!");
        }
    }


    private static String encrypt(String pass, String plaintext) throws Exception
    {
        char[] password = pass.toCharArray();
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key skey = keyFact.generateSecret(pbeSpec);
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
        cDec.init(Cipher.ENCRYPT_MODE, skey);
        byte[] input = CryptoUtils.toByteArray(plaintext);
        return CryptoUtils.toString(salt) + CryptoUtils.toString(cDec.doFinal(input));
    }

    private static String decrypt(String pass, String text) throws Exception
    {
        char[] password = pass.toCharArray();
        String saltString = text.substring(0,8);
        String cipherText = text.substring(8);
        byte[] salt = CryptoUtils.toByteArray(saltString);
        byte[] cipher = CryptoUtils.toByteArray(cipherText);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key skey = keyFact.generateSecret(pbeSpec);
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
        cDec.init(Cipher.DECRYPT_MODE, skey);
        return CryptoUtils.toString(cDec.doFinal(cipher));
    }
}
