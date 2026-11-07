import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.io.InputStream;

// Only fixed isolated LAB destinations. No raw headers/body are emitted.
class Probe {
    record Reply(int status, String server, String body, String backend) {}
    static Reply get(String uri) throws Exception {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build();
        var req = HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(5)).GET().build();
        var response = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            String body = new String(stream.readNBytes(8192), java.nio.charset.StandardCharsets.UTF_8);
            return new Reply(response.statusCode(), response.headers().firstValue("server").orElse(""), body,
                response.headers().firstValue("x-lab-backend").orElse(""));
        }
    }
    public static void main(String[] args) {
        try {
            if (args.length != 1 || !args[0].matches("[a-f0-9]{32}")) throw new Exception();
            String marker = args[0];
            var health = get("http://nginx:8080/lab/health.jsp?probe=" + marker);
            var files = get("http://nginx:8080/files/");
            var hidden = get("http://nginx:8080/private/example.txt");
            var error = get("http://127.0.0.1:8080/missing-" + marker);
            boolean nginxVersion = (health.server + files.server + files.body).toLowerCase().contains("nginx/");
            boolean tomcatVersion = (error.server + error.body).contains("Apache Tomcat") || error.server.contains("Apache-Coyote");
            System.out.println("{\"proxy_ok\":" + (health.status == 200 && health.body.trim().equals("LAB_TOMCAT_OK") && health.backend.equals("tomcat"))
                + ",\"directory_listing_blocked\":" + (files.status == 403 || files.status == 404)
                + ",\"nginx_version_hidden\":" + !nginxVersion
                + ",\"private_path_blocked\":" + (hidden.status == 403 || hidden.status == 404)
                + ",\"tomcat_version_hidden\":" + (error.status == 404 && !tomcatVersion) + "}");
        } catch (Exception ignored) {
            System.out.println("{\"error_code\":\"http_probe_failed\"}"); System.exit(2);
        }
    }
}
