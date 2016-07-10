package component;

import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;


import abe.ABE;
import abe.Attribute;
import abe.Key;
import abe.SecretKey;
import schemes.RW13;


public class KGC {

	private String name;
	//the attribute list
	private Map<String, Attribute> attributePool =new HashMap<String, Attribute>();
	private ABE scheme;
	private Key msk;
	private Key pk;

	public KGC(String name) {
		this.name = name;
		this.scheme = new RW13();// need to be improved
	}
	
	public String getKGCName(){
		return this.name;
	} 

	public Map<String, Attribute> getAttributePool() {
		return attributePool;
	}

	// format "name : value"
	public void setAttributePool(String[] attributesSet) {

		for (int i = 0; i < attributesSet.length; i++) {
			StringTokenizer st = new StringTokenizer(attributesSet[i], ":");
			String name = st.nextToken().trim();
			String value = st.nextToken().trim();
			Attribute attr = new Attribute(name, value);
			attributePool.put(attributesSet[i], attr);
		}
	}

	public String initialization() {
		Key[] key = scheme.setup();
		pk = key[0];
		msk = key[1];
		return pk.toJSONString();
	}

	public String genSecretKey(String[] attrStrings) {

		int k = 0;
		for (int i = 0 ; i < attrStrings.length; i++) {

			Attribute attr = attributePool.get(attrStrings[i]);
			if (attr != null) {
				k++;
			}
		}
		
		Attribute[] legalAttributes = new Attribute[k];
		for (int i = 0,j = 0; i < attrStrings.length; i++) {

			Attribute attr = attributePool.get(attrStrings[i]);
			if (attr != null) {
                legalAttributes[j]=attr;
                j++;
			}
		}
		
		if (legalAttributes.length == 0 || legalAttributes == null)
			return null;
		SecretKey sk = scheme.keygen(pk, msk, legalAttributes);
		return sk.toJSONString();
	}
     
	
	
//	public static void main(String[] args) {
//
//		KGC kgc = new KGC("center");
//		String[] attributesSet ={"school:pku","academy:computer","����:ɽ��"};
//		kgc.setAttributePool(attributesSet);
//		kgc.initialization();
//		String[] attrStrings= {"school:pku","academy:computer","����:ɽ��"};
//		kgc.genSecretKey(attrStrings);
//
//	}
}