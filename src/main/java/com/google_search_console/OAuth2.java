package com.google_search_console;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.siteVerification.SiteVerification;
import com.google.api.services.siteVerification.model.SiteVerificationWebResourceResource;

import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OAuth2 {
    private static final String CREDENTIALS_FILE_PATH = "credentials.json";
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final String TOKENS_DIRECTORY_PATH = "tokens";

    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new FileReader(CREDENTIALS_FILE_PATH));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, Collections.singletonList("https://www.googleapis.com/auth/siteverification"))
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();

        // Get the credentials (this will prompt the user to authorize the application if not already authorized)
        Credential credential = getCredentials(HTTP_TRANSPORT);

        // Print the access token
        System.out.println("Access Token: " + credential.getAccessToken());
        System.out.println("Refresh Token: " + credential.getRefreshToken());

        checkWebResourceId(credential);
    }

    static void checkWebResourceId(Credential credential) throws GeneralSecurityException, IOException {
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();

        SiteVerification siteVerification = new SiteVerification.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
                .setApplicationName("Google-SiteVerificationSample/1.0")
                .build();

        // Define the web resource ID you want to check
        String webResourceId = "https://licencetotest.com";
        try {
            SiteVerificationWebResourceResource resource = siteVerification.webResource().get(webResourceId).execute();
            System.out.println("Web Resource ID exists: " + resource);
        } catch (Exception e) {
            System.out.println("Web Resource ID does not exist or you do not have access: " + e.getMessage());
            //generateMetaTagToken(siteVerification, webResourceId);
        }
    }

    private static void generateMetaTagToken(SiteVerification siteVerification, String webResourceId) {
        try {
            // Prepare the request body for the token API
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("verificationMethod", "META");
            Map<String, String> site = new HashMap<>();
            site.put("type", "SITE");
            site.put("identifier", webResourceId); // replace with your site URL
            requestBody.put("site", site);

            // Make the POST request to the token API
            JsonHttpContent content = new JsonHttpContent(JSON_FACTORY, requestBody);
            HttpRequest request = siteVerification.getRequestFactory().buildPostRequest(
                    new com.google.api.client.http.GenericUrl("https://www.googleapis.com/siteVerification/v1/token"),
                    content
            );
            request.setParser(JSON_FACTORY.createJsonObjectParser());
            HttpResponse response = request.execute();

            // Parse the response
            Map<String, Object> responseData = response.parseAs(HashMap.class);
            String token = (String) responseData.get("token");
            System.out.println("Meta Tag Token: " + token);

            // You can now use the token as needed, e.g., for further processing or verification

        } catch (IOException e) {
            System.out.println("Failed to generate meta tag token: " + e.getMessage());
        }
    }

}

