package com.shephertz.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
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

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

/**
 * @author Ashutosh
 *
 */
public class APIGatewayUtillity {
	/**
	 * @param args
	 * @throws ClientProtocolException
	 * @throws IOException
	 * @throws OAuthSystemException
	 * @throws OAuthProblemException
	 * @throws JSONException
	 */
	public static void main(String[] args) throws ClientProtocolException,
			IOException, OAuthSystemException, OAuthProblemException,
			JSONException {

		String clientId = "IAM_KEY";
		String clientSecret = "IAM_Secret_KEY";
		String apiURLForAccessToken = "apiURL";

		/*
		 * -------Below Values & Method Call needed for CLient ID Access
		 * Token-------
		 */

		/*String grantType = "client_credentials";
		String accesstoken = getAccessToken(apiURLForAccessToken, grantType,
				clientId, clientSecret);
		System.out.println("Grant Type - Client ID Access Token: "
				+ accesstoken);*/

		
		
		
		/*
		 ---------Below Values & Method Call needed for Authorization AccessToken-----
		 */

		/*
		  String redirect_uri = "https://api.shephertz.com/"; 
		  String accesstoken = getAuthorizationAccessToken(clientId,clientSecret,apiURLForAccessToken,redirect_uri);
		  System.out.println("Grant Type - Authorization Access Token: "
		  +accesstoken);*/
		 
		
		

		/*
		  ----------Below Values & Method Call needed To GenerateSignature--------
		 */

		
		 /* String apiName = "apiName";
		  String version = "apiVersion";
		  String body = "";
		  String signature = generateSignature(apiName,version,IAM_KEY,IAM_Secret_KEY,body);
		  System.out.println("Signature: "+signature);
		 */
		

	}

	/**
	 * @param clientId
	 * @param clientSecret
	 * @param tokenEndPoint
	 * @param redirectURI
	 * @return
	 * @throws OAuthSystemException
	 * @throws OAuthProblemException
	 * @throws IOException
	 * @throws JSONException
	 */
	
	
	 public static InputStream getCall(URL url) throws IOException {
		// 
		 HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		 connection.setRequestMethod("GET");
		 connection.connect();

		 InputStream code =  connection.getInputStream();
		return code;
		 }
	
	private static String getAuthorizationAccessToken(String clientId,
			String clientSecret, String tokenEndPoint, String redirectURI)
			throws OAuthSystemException, OAuthProblemException, IOException,
			JSONException {
		String authCode = getAuthCode(tokenEndPoint, "code", clientId,
				redirectURI, "8ff721eaf87aee4de8278893f598c7e8", "ajay:profile");
		System.out.println("authCode"+authCode);
		System.out.println("authCode"+authCode.getClass());
		JSONObject authCodeObj = new JSONObject(authCode);
		System.out.println(authCodeObj.toString());
		OAuthClientRequest request = OAuthClientRequest
				.tokenLocation(tokenEndPoint + "/token").setClientId(clientId)
				.setClientSecret(clientSecret)
				.setCode(authCodeObj.get("code").toString())
				.setGrantType(GrantType.AUTHORIZATION_CODE)
				.setRedirectURI(redirectURI).buildQueryMessage();
		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		OAuthJSONAccessTokenResponse response = oAuthClient.accessToken(request);
		return response.getBody();

	}

	
	/**
	 * @param apiURLForAccessToken
	 * @param grantType
	 * @param clientId
	 * @param clientSecret
	 * @return
	 * @throws IOException
	 */
	public static String getAccessToken(String apiURLForAccessToken,
			String grantType, String clientId, String clientSecret)
			throws IOException {
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(apiURLForAccessToken
				+ "/token?grant_type=" + grantType + "&client_Id=" + clientId
				+ "&client_Secret=" + clientSecret);
		post.addHeader("Content-Type", "application/x-www-form-urlencoded");
		HttpResponse response = client.execute(post);
		BufferedReader rd = new BufferedReader(new InputStreamReader(response
				.getEntity().getContent()));
		return rd.readLine();
	}

	/**
	 * @param apiURLForAuthorizationToken
	 * @param response_type
	 * @param clientId
	 * @param redirect_uri
	 * @param state
	 * @param scope
	 * @return
	 * @throws IOException
	 */
	public static String getAuthCode(String apiURLForAuthorizationToken,
			String response_type, String clientId, String redirect_uri,
			String state, String scope) throws IOException {
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(apiURLForAuthorizationToken
				+ "/authorize?response_type=" + response_type + "&client_id="
				+ clientId + "&redirect_uri=" + redirect_uri + "&state="
				+ state + "&scope=" + scope);
		post.addHeader("Content-Type", "application/x-www-form-urlencoded");
		HttpResponse response = client.execute(post);
		BufferedReader rd = new BufferedReader(new InputStreamReader(response
				.getEntity().getContent()));
		String authCode = rd.readLine();
		System.out.println("printing this"+authCode);
		return authCode;
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

	public static String getUTCFormattedTimestamp() {
		SimpleDateFormat df = new SimpleDateFormat(
				"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		String dateStr = df.format(new Date());
		System.out.println("Timestamp: " + dateStr);
		return dateStr;
	}

	public String getUTCFormattedTimestamp(Date date) {
		SimpleDateFormat df = new SimpleDateFormat(
				"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(date);
	}

	public static String getUTCDate() {
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.format(new Date());
	}

	public static boolean isDecoded(String value) {
		if (value != null && (value.indexOf("%") == -1)) {
			return true;
		} else {
			return false;
		}
	}
}
