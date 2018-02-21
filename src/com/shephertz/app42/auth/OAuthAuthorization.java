package com.shephertz.app42.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
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
 * @author Naveen Goswami
 *
 */
public class OAuthAuthorization {

	public static void main(String[] args) throws OAuthSystemException, OAuthProblemException, IOException, JSONException {

		String iamKay = "<IAM Key>";
		String secretKey = "<Secret Key>";
		String apiURLForAccessToken = "<API URL>";
		String redirect_uri = "<Redirect URI>"; 

		String accesstoken = getAuthorizationAccessToken(iamKay,secretKey,apiURLForAccessToken,redirect_uri);
		System.out.println("Grant Type - Authorization Access Token: " +accesstoken);
		
	}

	private static String getAuthorizationAccessToken(String clientId,
			String clientSecret, String tokenEndPoint, String redirectURI)
			throws OAuthSystemException, OAuthProblemException, IOException,
			JSONException {
		String authCode = getAuthCode(tokenEndPoint, "code", clientId,
				redirectURI, "8ff721eaf87aee4de8278893f598c7e8", "ajay:profile");
		JSONObject authCodeObj = new JSONObject(authCode);
		System.out.println("Grant Type - Authorization Code: " + authCodeObj.toString());
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
		return authCode;
	}

}
