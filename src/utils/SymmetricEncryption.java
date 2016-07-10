package utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import java.util.Scanner;


public class SymmetricEncryption {

	public byte[] encrypt(byte[] content, byte[] encryptKey) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128, new SecureRandom(encryptKey));

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));

		return cipher.doFinal(content);
	}

//	public byte[] decrypt(byte[] encryptBytes, byte[] decryptKey) throws Exception {
//		KeyGenerator kgen = KeyGenerator.getInstance("AES");
//		kgen.init(128, new SecureRandom(decryptKey));
//
//		Cipher cipher = Cipher.getInstance("AES");
//		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
//		byte[] decryptBytes = cipher.doFinal(encryptBytes);
//
//		return decryptBytes;
//	}
    
	public byte[] encrypt(File sourceFile, byte[] encryptKey) throws Exception {

		FileInputStream inputStream = null;
		ByteArrayOutputStream outputStream = null;
		byte[] encrptedBytes = null;
		try {
			// set the input source
			inputStream = new FileInputStream(sourceFile);
			outputStream = new ByteArrayOutputStream();
 
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(encryptKey));
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
			CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
			
			byte[] cache = new byte[20480];  //file's max sise: 20MB
			int nRead = 0;
			while ((nRead = cipherInputStream.read(cache)) != -1) {
				outputStream.write(cache, 0, nRead);
				outputStream.flush();
			}
			encrptedBytes= outputStream.toByteArray();
			
			cipherInputStream.close();
			
						
		} catch (FileNotFoundException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} catch (IOException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} finally {
			try {
				inputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
			try {
				outputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
		}
		return encrptedBytes;
	}

	public byte[] decrypt(byte[] sourceBytes, byte[] decryptKey) throws Exception {
		
		byte[] clearBytes = null;
		ByteArrayInputStream inputStream = null;
		ByteArrayOutputStream outputStream = null;
		try {
					
			// init AES
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(decryptKey));
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
			
			inputStream = new ByteArrayInputStream(sourceBytes);
			outputStream = new ByteArrayOutputStream();
			CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
			byte[] buffer = new byte[20480];   //20MB
			int r;
			while ((r = inputStream.read(buffer)) >= 0) {
				cipherOutputStream.write(buffer, 0, r);
			}
			cipherOutputStream.close();
			clearBytes = outputStream.toByteArray();
		} catch (IOException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} finally {
			try {
				inputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
			try {
				outputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
		}
		return clearBytes;
	}

	public static void main(String[] args) throws Exception {

		SymmetricEncryption se = new SymmetricEncryption();
		
		//test one
		Scanner scanner =new Scanner(System.in);
		//"hello world".getBytes("utf-8")
		byte[] cipertext = se.encrypt(scanner.nextLine().getBytes("utf-8"), "231".getBytes());
		byte[] cleartext = se.decrypt(cipertext, "231".getBytes());
		String test = new String(cleartext, "utf-8");
		System.out.println(test);
		
		//test two
//		byte[] key ="haha".getBytes();
//		File inputFile =new File("C:/Users/Lenovo/Desktop/1.jpg");
//		byte[] encBytes = se.encrypt(inputFile, key);
//		 FileOutputStream filetmpOut = new FileOutputStream("C:/Users/Lenovo/Desktop/tmp");
//		    filetmpOut.write(encBytes);
//		    filetmpOut.close();
//		byte[] decBytes = se.decrypt(encBytes , key);
//	    FileOutputStream fileOut = new FileOutputStream("C:/Users/Lenovo/Desktop/2.jpg");
//	    fileOut.write(decBytes);
//	    fileOut.close();
	}

}
