/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ao.atlantico.decryapp;

/**
 *
 * @author upn03008
 */

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
//import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author uja02663
 */
public class EncriptarBankaPWD {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        try {
            String username = "bpmadmin"; // Coloca aqui o Username
            String password = "bUxjPKgbTNY8Z6c0lp41"; // coloca aqui a Password
            //String x = "c2lA5NdQam0cGeVuy0xEzg==:QlDWrPmBv3nazMD2n8OVQw==";
            //String x = "CR44Iwt0PLMLQfSU+kf+gQ==:ZoSgkr+SgdsHUdqu1S3lwg==";
            // The salt (probably) can be stored along with the encrypted data
            byte[] salt = username.getBytes();
            
            // Decreasing this speeds down startup time and can be useful during testing, but it also makes it easier for brute force attackers
            int iterationCount = 40000;
            // Other values give me java.security.InvalidKeyException: Illegal key size or default parameters
            int keyLength = 128;
            SecretKeySpec key = createSecretKey(username.toCharArray(),salt, iterationCount, keyLength);
            
            String originalPassword = password;
            System.out.println("Original password: " + originalPassword);
            String encryptedPassword = encrypt(password, key);
            System.out.println("Encrypted password: " + encryptedPassword);
            String decryptedPassword = decrypt(encryptedPassword, key);
            System.out.println("Decrypted password: " + decryptedPassword);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(EncriptarBankaPWD.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException | IOException ex) {
            Logger.getLogger(EncriptarBankaPWD.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(EncriptarBankaPWD.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        //SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }
    
    public static String encrypt(String property, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters parameters = pbeCipher.getParameters();
        IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
        byte[] cryptoText = pbeCipher.doFinal(property.getBytes("UTF-8"));
        byte[] iv = ivParameterSpec.getIV();
        return base64Encode(iv) + ":" + base64Encode(cryptoText);
    }
    
     public static String decrypt(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
        String iv = string.split(":")[0];
        String property = string.split(":")[1];
        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
        return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
    }
    
    public static String base64Encode(byte[] bytes) {
        //return Base64.getEncoder().encodeToString(bytes);
        return DatatypeConverter.printBase64Binary(bytes);
    }
    
    public static byte[] base64Decode(String property) throws IOException {
        //return Base64.getDecoder().decode(property);
        return DatatypeConverter.parseBase64Binary(property);
    }
    
}

