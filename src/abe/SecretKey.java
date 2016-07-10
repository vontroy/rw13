package abe;

/*
 * author: wenzilong,licong
 */

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import com.alibaba.fastjson.JSONObject;

public class SecretKey extends Key{
	private Attribute[] attributes;

	public SecretKey(){
		super(Type.SECRET);
	}
	
	public void setAttributes(Attribute[] attributes){
		this.attributes = attributes;
	}
	
	public Attribute[] getAttributes(){
		return attributes;
	}
	
	public static String attributesToString(Attribute[] attributes){
		
		String str="";
		for(int i=0; i<attributes.length; i++){
			if(i==0)
			str+=attributes[i].toString();
			else
			str+="_"+attributes[i].toString();
		}	
	   return str;
	}
	
	@Override   
	public String toJSONString() {
		JSONObject obj = new JSONObject();
		obj.put("type", type);
		obj.put("attributes", attributesToString(this.attributes));
		obj.put("attrnum", this.attributes.length);
		for(Map.Entry<String, Element> entry : this.components.entrySet()){
			obj.put(entry.getKey(), entry.getValue().toBytes());
		}
		return obj.toJSONString();
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append("Type:" + getType() + "\n");
		sb.append("Attributes:{\n");
		for(int i=0; i<attributes.length; i++)
			sb.append(attributes[i] + "\t");
		sb.append("}\n");
		sb.append("Components:{\n");
		for(Map.Entry<String, Element> element : getComponents().entrySet()){
			sb.append(element.getKey() + "----> " + element.getValue() + "\n");
		}
		sb.append("}");
		return sb.toString();
	}
}
