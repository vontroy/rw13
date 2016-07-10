package example;

import component.KGC;

public class TestExample {

	public static void main(String[] args) throws Exception {

		Example example = new Example();

		KGC kgc = new KGC("center");
		String[] attributesSet = { "school:pku", "academy:computer", "籍贯:北京", "age:130" };
		kgc.setAttributePool(attributesSet);

		// obtain the pk;
		String jsonPK = kgc.initialization();

		// obtain the sk;
		String[] attrStrings = {"school:pku"};
		//, "籍贯:北京" 
		String jsonSK = kgc.genSecretKey(attrStrings);

		// obtain the ciphertext
//		String policy = "school:pku or academy:computer or 籍贯:北京";
		String policy = "(school:pku and academy:computer) or (籍贯:北京  and age:130)";
		String fileURL = "C:/Users/wenzilong/Desktop/1.jpg";
		String targetDirURL = "C:/Users/wenzilong/Desktop";
		String ciphertextURL = example.encFile(fileURL, targetDirURL, policy,
				jsonPK, "try it!".getBytes(), "jack");

		// obtain the plaintext
		boolean flag = example.decFile(ciphertextURL, targetDirURL, jsonSK,
				"jerry");
		if (flag)
			System.out.println("Decryption Operates Successfully!");
		else
			System.out.println("Decryption Operates Unsuccessfully!");
	}
}