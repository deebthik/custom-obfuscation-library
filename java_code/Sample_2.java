

import java.lang.Math;
import java.util.Random;

import java.io.File; 
import java.io.FileNotFoundException;  
import java.util.Scanner;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.*;  



public class Sample_2{

    public static void main(String []args) {

		/*String og_data = "Bearer eyJhbGciOiJIUzUxMiJ9.eyJtb2JpbGVOdW1lciI6Ijk5NjI0MzM5OTMiLCJleHAiOjE2MjIzODMwNDQsInVzZXJJZCI6Ijc0aEhlZlVTejBxRzVNOFNLQWFwRjNqYzdnPT0iLCJoYXNoIjoiMjAyYzQyNzJlOTgyMjYzYjRlMzRhNGRlNzhhZDY3ZDgiLCJrZXkiOiJERVZJQ0VfNzM1IiwidXNlcm5hbWUiOiI5OTYyNDMzOTkzIn0.9s3geYQb-gxzfMJfdHmEUWXcSXr5bxk6Mlpzwm8LYx8EmyKappe8gt0n9SIBCxLIh6Rgu2RVamEobzz133B8nQ";
		System.out.println("Original Data -> " + og_data + "\n");

		//String a = Obfuscation.obfuscate("Bearer eyJhbGciOiJIUzUxMiJ9.eyJtb2JpbGVOdW1lciI6Ijk5NjI0MzM5OTMiLCJleHAiOjE2MjIzODMwNDQsInVzZXJJZCI6Ijc0aEhlZlVTejBxRzVNOFNLQWFwRjNqYzdnPT0iLCJoYXNoIjoiMjAyYzQyNzJlOTgyMjYzYjRlMzRhNGRlNzhhZDY3ZDgiLCJrZXkiOiJERVZJQ0VfNzM1IiwidXNlcm5hbWUiOiI5OTYyNDMzOTkzIn0.9s3geYQb-gxzfMJfdHmEUWXcSXr5bxk6Mlpzwm8LYx8EmyKappe8gt0n9SIBCxLIh6Rgu2RVamEobzz133B8nQ");
		String a = Obfuscation.obfuscate(og_data);
		System.out.println("Obfuscated Data -> " + a + "\n");

		String b = Obfuscation.deobfuscate(a);
		System.out.println("Deobfuscated Data -> " + b + "\n");

		if (og_data.equals(b)){
			System.out.println("\nSUCCESSFUL!\n");
		}*/

/*
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
	*/	
	

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


		String obfuscated = "";

		try{

			File myObj = new File("/home/deebthik/Desktop/obfuscation_test/obfuscated.txt");
			Scanner myReader = new Scanner(myObj);
			while (myReader.hasNextLine()) {
				obfuscated = myReader.nextLine();
				//System.out.println(data);
			}

		myReader.close();

		} catch (FileNotFoundException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}


		System.out.println("\nObfuscated token -> " + obfuscated + "\n");

		
		String og = "";

		try{

			File myObj = new File("/home/deebthik/Desktop/obfuscation_test/og.txt");
			Scanner myReader = new Scanner(myObj);
			while (myReader.hasNextLine()) {
				og = myReader.nextLine();
				//System.out.println(data);
			}

		myReader.close();

		} catch (FileNotFoundException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}


		System.out.println("\n" + "OG token -> --------" + og + "----------\n");


	
		String deobfuscated = Obfuscation.deobfuscate(obfuscated);
		System.out.println("\n" + "Deobfuscated token -> -----------" + deobfuscated + "--------------\n");
		

		if (og.equals(deobfuscated)){
	
			System.out.println("\nEUREKA!\n");

		} else{

			System.out.println("\nSIGH!\n");

		}



	}



public static String[] difference(String a, String b) {
    return diffHelper(a, b, new HashMap<>());
}

private static String[] diffHelper(String a, String b, Map<Long, String[]> lookup) {
    return lookup.computeIfAbsent(((long) a.length()) << 32 | b.length(), k -> {
        if (a.isEmpty() || b.isEmpty()) {
            return new String[]{a, b};
        } else if (a.charAt(0) == b.charAt(0)) {
            return diffHelper(a.substring(1), b.substring(1), lookup);
        } else {
            String[] aa = diffHelper(a.substring(1), b, lookup);
            String[] bb = diffHelper(a, b.substring(1), lookup);
            if (aa[0].length() + aa[1].length() < bb[0].length() + bb[1].length()) {
                return new String[]{a.charAt(0) + aa[0], aa[1]};
            } else {
                return new String[]{bb[0], b.charAt(0) + bb[1]};
            }
        }
    });
}



}





