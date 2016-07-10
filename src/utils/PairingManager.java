package utils;
/*
 * author: licong
 */
import java.io.InputStream;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

public class PairingManager {
	
	private static final String TYPE_A = "/curves/a.properties";
//	private static final String TYPE_A = "/src/curves/a.properties";
//	private static final String TYPE_A = "/utils/a.properties"; //for jar
	
	public static Pairing getDefaultPairing(){
		
//		String url=PairingManager.class.getResource("/").toString();
//		String newUrl = url.substring(6, url.length()-5);
//		newUrl += TYPE_A;
////		System.out.println(newUrl);
//		return PairingFactory.getPairing(new PropertiesParameters().load(newUrl));
		InputStream is = PairingManager.class.getClass().getResourceAsStream(TYPE_A);
//		InputStream is = PairingManager.class.getResourceAsStream(TYPE_A);
		return PairingFactory.getPairing(new PropertiesParameters().load(is));
	}
}
