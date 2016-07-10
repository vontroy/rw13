package component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import abe.ABE;
import abe.Ciphertext;
import abe.SecretKey;
import schemes.RW13;
import utils.Deserialization;
import utils.SymmetricEncryption;

public class Decryptor {
   
	 private String name;
	 private ABE scheme;
	 private SymmetricEncryption se;
	 private Logger logger = LoggerFactory.getLogger(Encryptor.class);
	 
	 public Decryptor(String name){
		 this.name = name;
		 this.scheme = new RW13();
		 this.se =new SymmetricEncryption();
	 }

	 public String getDecryptorName(){	 
		 return this.name;
	 }

	 
	 /**
      * @return plaintext in form of byte[] , otherwise (failure) return null;
	 **/
	 public byte[] decrypt(String objCiphertext, String objSecretKey) throws Exception{
		 
   	    return this.basedecrption(objCiphertext, objSecretKey);
    }


	 private byte[] basedecrption(String objCiphertext, String objSecretKey) throws Exception{
		   
		   if(objCiphertext==null) {
			   logger.error("Require Ciphertext!");
		   }
		   else if (objSecretKey==null){
			   logger.error("Require SecretKey!");
		   }
		  
		   byte[] decryptedBytes = null;
		   SecretKey sk = Deserialization.toSecretKey(objSecretKey);
		   Ciphertext ct = Deserialization.toCiphertext(objCiphertext);
		   
		   byte[] symmetricKey = scheme.decrypt(ct , sk);
		   
		   //ABE decrypt unsuccessfully;
		   if(symmetricKey==null){
			   return null;
		   }
	   
		   decryptedBytes= se.decrypt(ct.getLoad(),symmetricKey);
		   if(decryptedBytes==null){
			   logger.error("AES cipertext is null!");
			   return null;
		   }
		   return decryptedBytes;
		 }
}