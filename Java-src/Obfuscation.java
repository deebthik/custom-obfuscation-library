package com.deebthik.random.lightweight_obfuscation.obfuscation;


import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.*;
import java.nio.charset.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.stream.Collectors;
import java.util.zip.Checksum;
import java.util.zip.CRC32;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.Math;
import java.util.Random;






public final class Obfuscation {



/*-----------------------AES encrypt/decrypt funcs-------------------*/



public static String AES_encrypt(String plainText, String encryptionKey, String IV) {

	try 
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
		return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")));
	}
	catch (Exception e){
		System.out.println("Error while encrypting: " + e.toString());
	}
	return null;

  }


public static String AES_decrypt(String cipherText, String encryptionKey, String IV) {
	
	try
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
		return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
	}
	catch (Exception e){
		System.out.println("Error while decrypting: " + e.toString());
	}
	return null;

  }


/*----------------------------------------*/




/*----------------Hashing funcs--------------*/



 public static String getSha256(String value) {
    try{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(value.getBytes());
        return bytesToHex(md.digest());
    } catch(Exception ex){
        throw new RuntimeException(ex);
    }
 }
 private static String bytesToHex(byte[] bytes) {
    StringBuffer result = new StringBuffer();
    for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
    return result.toString();
 }


/*----------------------------------------*/


/*------------XOR funcs----------------*/

	static String addZeros(String str, int n)
    {
        for (int i = 0; i < n; i++)
        {
            str = "0" + str;
        }
        return str;
    }


	static String getXOR(String a, String b)
    {

        // Lengths of the given strings
        int aLen = a.length();
        int bLen = b.length();

        // Make both the strings of equal lengths
        // by inserting 0s in the beginning
        if (aLen > bLen)
        {
            a = addZeros(b, aLen - bLen);
        }
        else if (bLen > aLen)
        {
            a = addZeros(a, bLen - aLen);
        }

        // Updated length
        int len = Math.max(aLen, bLen);

        // To store the resultant XOR
        String res = "";

        for (int i = 0; i < len; i++)
        {
            if (a.charAt(i) == b.charAt(i))
                res += "0";
            else
                res += "1";
        }
        return res;
    }

/*----------------------------------------*/



/*--------------Hex2bin func--------------*/


	// declaring the method to convert
    // Hexadecimal to Binary
    static String hexToBinary(String hex)
    {

        // variable to store the converted
        // Binary Sequence
        String binary = "";

        // converting the accepted Hexadecimal
        // string to upper case
        hex = hex.toUpperCase();

        // initializing the HashMap class
        HashMap<Character, String> hashMap
            = new HashMap<Character, String>();

        // storing the key value pairs
        hashMap.put('0', "0000");
        hashMap.put('1', "0001");
        hashMap.put('2', "0010");
        hashMap.put('3', "0011");
        hashMap.put('4', "0100");
        hashMap.put('5', "0101");
        hashMap.put('6', "0110");
        hashMap.put('7', "0111");
        hashMap.put('8', "1000");
        hashMap.put('9', "1001");
        hashMap.put('A', "1010");
        hashMap.put('B', "1011");
        hashMap.put('C', "1100");
        hashMap.put('D', "1101");
        hashMap.put('E', "1110");
        hashMap.put('F', "1111");

        int i;
        char ch;

        // loop to iterate through the length
        // of the Hexadecimal String
        for (i = 0; i < hex.length(); i++) {
            // extracting each character
            ch = hex.charAt(i);

            // checking if the character is
            // present in the keys
            if (hashMap.containsKey(ch))

                // adding to the Binary Sequence
                // the corresponding value of
                // the key
                binary += hashMap.get(ch);

            // returning Invalid Hexadecimal
            // String if the character is
            // not present in the keys
            else {
                binary = "Invalid Hexadecimal String";
                return binary;
            }
        }

        // returning the converted Binary
        return binary;
    }


/*----------------------------------------*/



/*---------------String repeat func------------------*/



	public static String repeatString(String s,int count){
		StringBuilder r = new StringBuilder();
		for (int i = 0; i < count; i++) {
		    r.append(s);
		}
		return r.toString();
	}


/*----------------------------------------*/



/*----------------Obfuscation func---------------------*/

	public static String obfuscate (String data) {

			//generating random 16 bytes -> key for AES encryption
			byte[] array_secretKey = new byte[16];
			new Random().nextBytes(array_secretKey);


			//encoding
			String secretKey_hex = "";
			for (byte i : array_secretKey) {
				secretKey_hex += String.format("%02x", i);
				
			}

			//stripping off leading zero to avoid problems with XORing with binary strings later on
			secretKey_hex = secretKey_hex.replaceFirst("^0+(?!$)", "");
			//final secret key would be the first 16 chars of secretKey_hex
			String secretKey_final = secretKey_hex.substring(0, 16);
			String secretKey_binstr = hexToBinary(secretKey_hex);


			byte[] array_iv = new byte[16]; 
			new Random().nextBytes(array_iv);

			//encoding
			String iv_hex = "";
			for (byte i : array_iv) {
				iv_hex += String.format("%02x", i);
			}
			////final iv would be the first 16 chars of iv_hex
			String iv_final = iv_hex.substring(0, 16);

			//padding_data_wrtmultipleof16bytes	for AES
			data += repeatString("\u0000", 16 * ( (data.length()/16) + 1 ) - data.length() );


			//encrypting the given data
			//String encryptedString = AES_encrypt(data, "m92oQ/oo1LhQW3hM", "3jBcIwdmJ/1Yt30v");
			String encryptedString = AES_encrypt(data, secretKey_final, iv_final);

			//get hash of encryptedString/ciphertext
      		String encryptedString_hash = getSha256(encryptedString);
			String encryptedString_hash_binstr = hexToBinary(encryptedString_hash);


			//XORing the key and encryptedString/ciphertext
			String xored_key_binstr = getXOR(secretKey_binstr, encryptedString_hash_binstr);


			//encoding
			BigInteger xored_key_int = new BigInteger(xored_key_binstr, 2);
			String xored_key_hex = xored_key_int.toString(16);
			xored_key_hex = repeatString("0", (64-xored_key_hex.length())) + xored_key_hex;
			String xored_key_base64 = Base64.getEncoder().encodeToString(new BigInteger(xored_key_hex, 16).toByteArray());

			//concatenating the encrypted data, xored key and ivi
			//preprefinalmsg => ciphertext in base64 + xoredkey in hex + iv_final in hex
			String preprefinalmsg = encryptedString + xored_key_hex + iv_final;


			//taking crc32 of above, converting to hex and appending it -> first layer
			CRC32 crc1 = new CRC32();
			crc1.update(preprefinalmsg.getBytes());
			String crc1_hex = Long.toHexString(crc1.getValue());
			//adding leading 0 in case hex is lot 8 chars long, to ensure that there will be a constant placeholder for extracting the crc while deobfuscation
			crc1_hex = repeatString("0", (8-crc1_hex.length())) + crc1_hex;
			String prefinalmsg = preprefinalmsg + crc1_hex;



			//taking crc32 of above, converting to hex and appending it -> first layer -> second layer
			CRC32 crc2 = new CRC32();
			crc2.update(prefinalmsg.getBytes());
			String crc2_hex = Long.toHexString(crc2.getValue());
			crc2_hex = repeatString("0", (8-crc2_hex.length())) + crc2_hex;
			String finalmsg = crc2_hex + prefinalmsg;



			//final msg -> (encrypted_data + xored_key + ivi) + crc32(encrypted_data + xored_key + ivi) + crc32(crc32(encrypted_data + xored_key))

			//System.out.println(finalmsg);
			return finalmsg;

		
	}


/*----------------------------------------*/



/*---------------Deobfuscate func----------------*/


	public static String deobfuscate (String data) {

		if (data.length() <= 8){

			System.out.println("INVALID OBFUSCATED STRING!");
			//System.exit(1);
			return null;

		}

		String finalmsg = data;

		//extracting second layer of crc32 and verifying integrity
		String crc2_hex = finalmsg.substring(0, 8);

		String prefinalmsg = finalmsg.substring(8, finalmsg.length());
					
		CRC32 crc2 = new CRC32();
		crc2.update(prefinalmsg.getBytes());
		String crc2_hex_final = Long.toHexString(crc2.getValue());
		crc2_hex_final = repeatString("0", (8-crc2_hex_final.length())) + crc2_hex_final;


		if ( !crc2_hex.equals(crc2_hex_final) ){

			System.out.println("\nIntegrity check failed, obfuscated message is corrupted or invalid!");
			//System.exit(1);
			return null;

		}


		//extracting second layer of crc32 and verifying integrity
		String crc1_hex = prefinalmsg.substring(prefinalmsg.length()-8, prefinalmsg.length());

		String preprefinalmsg = prefinalmsg.substring(0, prefinalmsg.length()-8);

		CRC32 crc1 = new CRC32();
		crc1.update(preprefinalmsg.getBytes());
		String crc1_hex_final = Long.toHexString(crc1.getValue());
		crc1_hex_final = repeatString("0", (8-crc1_hex_final.length())) + crc1_hex_final;


		if ( !crc1_hex.equals(crc1_hex_final) ){

				System.out.println("\nIntegrity check failed, obfuscated message is corrupted or invalid!");
				//System.exit(1);
				return null;

		}



		//extracing iv, xored key and encrypted msg separately from (encrypted msg + xored key) (the iv and xored key since of constant sizes, can be stripped off leaving back the encrypted msg, which maybe of variable size)
		String iv_final = preprefinalmsg.substring(preprefinalmsg.length()-16, preprefinalmsg.length());
		String xored_key_hex = preprefinalmsg.substring(preprefinalmsg.length()-80, preprefinalmsg.length()-16);
		String encryptedString = preprefinalmsg.substring(0, preprefinalmsg.length()-80);

		//decoding
		String encryptedString_hash = getSha256(encryptedString);
		String encryptedString_hash_binstr = hexToBinary(encryptedString_hash);


		//decoding
		String xored_key_binstr = hexToBinary(xored_key_hex);

		//xoring the xored key and encrypted msg to get back the original key
		String secretKey_binstr = getXOR(xored_key_binstr, encryptedString_hash_binstr);
		String secretKey_binstr_final = secretKey_binstr.substring(secretKey_binstr.length()-128, secretKey_binstr.length());

		//decoding
		BigInteger secretKey_int = new BigInteger(secretKey_binstr_final, 2);
		String secretKey_hex = secretKey_int.toString(16).replaceFirst("^0+(?!$)", "");	

		String secretKey_final = secretKey_hex.substring(0, 16);

		//using the original key to decrypt the msg
		String decryptedString = AES_decrypt(encryptedString, secretKey_final, iv_final);
		decryptedString = decryptedString.trim();
		//String decryptedString = AES_decrypt("QW1BuF8o+nMtPUauyWJ3NEgkuri9D4INOMJ05HnDgOZRoKQR8K+NIbFlzkHtLTuK", "6a/QD5Z4zfIviIHJ", "jGtJzRDA4/ON15lV");


		/*System.out.println("\njava ciphertextbase64 ------> " + encryptedString + "\n");
		System.out.println("\njava xoredkeyhex ------> " + xored_key_hex + "\n");
		System.out.println("\njava ivfinal ------> " + iv_final + "\n");
		System.out.println("\nsecretkeyfinal ------> " + secretKey_final + "\n");
		System.out.println("\nxored_key_binstr ------> " + xored_key_binstr + "\n");
		System.out.println("\nsecretKey_binstr ------> " + secretKey_binstr + "\n");
		System.out.println("\nsecretKey_hex ------> " + secretKey_hex + "\n");*/

		return decryptedString;


	}


/*----------------------------------------*/





	public static void main(String[] args) {


		//SAMPLE CALLS
		//System.out.println("Obfuscated string -> " + obfuscate(""));
		//System.out.println("Deobfuscated string -> " + deobfuscate(obfuscate("")));
		//System.out.println("Deobfuscated string -> " + deobfuscate("fteethethet"));


	}






}
