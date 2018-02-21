package com.shephertz.app42.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * @author Naveen Goswami
 *
 */

public class OAuthClientId {

	public static void main(String[] args) throws IOException {
		
		String iamKay = "<IAM Key>";
		String secretKey = "<Secret Key>";
		String apiURLForAccessToken = "<API URL>";

		String grantType = "client_credentials";
		String accesstoken = getAccessToken(apiURLForAccessToken, grantType,
				iamKay, secretKey);
		System.out.println("Grant Type - Client ID Access Token: "
				+ accesstoken);



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

}
