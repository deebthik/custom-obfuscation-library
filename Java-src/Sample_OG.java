import com.deebthik.random.lightweight_obfuscation.obfuscation;


import java.lang.Math;
import java.util.Random;

import java.io.File; 
import java.io.FileNotFoundException;  
import java.util.Scanner;
import java.io.FileWriter;
import java.io.IOException; 



public class Sample_OG{

    public static void main(String []args) {

		
		//TEST WITH RANDOM STRINGS OF VARIOUS LENGTHS
		// create a string of all characters
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=.:;";

		// create random string builder
		StringBuilder sb = new StringBuilder();

		// create an object of Random class
		Random random = new Random();

		// specify length of random string
		Random rand = new Random();
		int length = rand.nextInt(1000)+1;

		for(int i = 0; i < length; i++) {

		  // generate random index number
		  int index = random.nextInt(alphabet.length());

		  // get character specified by index
		  // from the string
		  char randomChar = alphabet.charAt(index);

		  // append the character to string builder
		  sb.append(randomChar);
		}


		String randomString = sb.toString();
		System.out.println("\nInput Data -> "+randomString+"\n");

		String randomString_obfuscated = Obfuscation.obfuscate(randomString);	
		System.out.println("\nObfuscated Data -> "+randomString_obfuscated+"\n");

		String randomString_deobfuscated = Obfuscation.deobfuscate(randomString_obfuscated);
		System.out.println("\nDeobfuscated Data -> "+randomString_deobfuscated+"\n");


		if (randomString_deobfuscated.equals(randomString)){
			System.out.println("\nSTRINGS ARE EQUAL!\n");
		}else{
			System.out.println("\nSTRINGS ARE NOT EQUAL!\n");
		}
		



	}


}





