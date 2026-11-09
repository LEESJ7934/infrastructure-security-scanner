import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.io.InputStream;
import java.util.LinkedHashMap;

// Fixed internal LAB destinations only. Public synthetic page contents, no login.
class SelectedProbe {
    static String quoted(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 32) b.append(String.format("\\u%04x",(int)c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static String get(String uri) throws Exception {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build();
        var request = HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(5)).GET().build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            String body = new String(stream.readNBytes(32768), java.nio.charset.StandardCharsets.UTF_8);
            return "{\"status\":"+response.statusCode()+",\"server\":"+quoted(response.headers().firstValue("server").orElse(""))
                +",\"x_powered_by\":"+quoted(response.headers().firstValue("x-powered-by").orElse(""))
                +",\"body\":"+quoted(body)+"}";
        }
    }
    public static void main(String[] args) throws Exception {
        var targets = new LinkedHashMap<String,String>();
        for (String product : new String[]{"nginx","tomcat"}) {
            String base="http://"+product+":8080";
            targets.put(product+"_normal",base+"/lab/health.jsp");
            targets.put(product+"_error",base+"/missing-kisa-selected");
            targets.put(product+"_directory",base+(product.equals("nginx")?"/files/":"/lab/files/"));
            targets.put(product+"_backup",base+(product.equals("nginx")?"/files/sample.bak":"/lab/files/sample.bak"));
            targets.put(product+"_docs",base+"/docs/");
            targets.put(product+"_examples",base+"/examples/");
        }
        StringBuilder out = new StringBuilder("{");
        for (var item : targets.entrySet()) {
            if (out.length()>1) out.append(',');
            out.append(quoted(item.getKey())).append(':').append(get(item.getValue()));
        }
        System.out.println(out.append('}'));
    }
}
