# App42_APIGatewayUtillity

Using this Utility , one can do the below things:

1. Generate Access token for OAuth Grant Type as CLient ID /Client Credentials.
2. Generate Access token for OAuth Grant Type as Authorization Code.
3. Generate Signature & Timestamp for Signature Validation.


One needs to provide the input in the method calls for iam key and secret key as well as API URL.


Note : To make this utility working, add the below jars in the build path of this project:

  1. apache-httpcomponents-httpcore.jar
  2. apache-httpcomponents-httpclient.jar
  3. commons-logging-1.2.jar
  4. org.apache.oltu.oauth2.client-0.31.jar
  5. jettison-1.3-sources.jar
  6. org.apache.oltu.oauth2.common-0.31.jar

