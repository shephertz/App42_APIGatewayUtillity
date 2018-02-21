package com.shephertz.app42.auth;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.TimeZone;
import java.util.Vector;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.shephertz.util.Base64;

/**
 * @author Naveen Goswami
 *
 */

public class KeyAuth {

	public static void main(String[] args) {
		String apiName = "<API Name>";
		String version = "<Version>";
		String iamKay = "<IAM Key>";
		String secretKey = "<Secret Key>";
		String body = "<Request Body>";
		
		String signature = generateSignature(apiName,version,iamKay,secretKey,body);
		System.out.println("Signature: "+signature);
		 
		
		

	}
	
	/**
	 * @param name
	 * @param version
	 * @param apiKey
	 * @param clientSecret
	 * @param body
	 * @return
	 */
	public static String generateSignature(String name, String version,
			String apiKey, String clientSecret, String body) {
		Hashtable<String, String> hashMap = new Hashtable<String, String>();
		hashMap.put("name", name);
		hashMap.put("version", version);
		hashMap.put("apiKey", apiKey);
		hashMap.put("timeStamp", getUTCFormattedTimestamp());
		hashMap.put("body", body);
		return sign(clientSecret,hashMap);

	}

	public static String getUTCFormattedTimestamp() {
		SimpleDateFormat df = new SimpleDateFormat(
				"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		String dateStr = df.format(new Date());
		System.out.println("Timestamp: " + dateStr);
		return dateStr;
	}

	/**
	 * Signs the request using HmacSha1
	 * 
	 * @params secretKey The key using which the signing has to be done
	 * @params params The parameters which have to be signed
	 */
	public static String sign(String secretKey, Hashtable params) {
		try {
			String sortedParams = sortAndConvertTableToString(params);
			String signature = computeHmac(sortedParams, secretKey);
			return java.net.URLEncoder.encode(signature);
		} catch (NoSuchAlgorithmException ex) {
			ex.printStackTrace();
		} catch (InvalidKeyException ex) {
			ex.printStackTrace();
		} catch (IllegalStateException ex) {
			ex.printStackTrace();
		} catch (UnsupportedEncodingException ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static String computeHmac(String baseString, String key)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance("HmacSHA1");
		SecretKeySpec secret = new SecretKeySpec(key.getBytes(),
				mac.getAlgorithm());
		mac.init(secret);
		byte[] digest = mac.doFinal(baseString.getBytes());
		return Base64.encodeBytes(digest);
	}

	/**
	 * Sorts the table keys alphatabically
	 * 
	 * @params table Key Value pairs which are sent as a payload to the REST
	 *         App42 Cloud API Server
	 */
	static String sortAndConvertTableToString(Hashtable table) {
		Vector v = new Vector(table.keySet());
		Collections.sort(v);
		StringBuffer requestString = new StringBuffer();
		for (Enumeration e = v.elements(); e.hasMoreElements();) {
			String key = (String) e.nextElement();
			String val = (String) table.get(key);
			requestString.append(key);
			requestString.append(val);
		}
		return requestString.toString();
	}



}
