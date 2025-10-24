# Real-World Curl Examples - Testing All Variations

## Problem: Different Shells, Different Quotes

### Windows Command Prompt
```batch
REM Windows uses double quotes
curl -X POST "https://api.example.com/data" -H "Content-Type: application/json" -d "{\"name\":\"John\"}"
```

### PowerShell
```powershell
# PowerShell with backticks
curl -X POST https://api.example.com/data `
     -H "Content-Type: application/json" `
     -d '{"name":"John"}'

# PowerShell with @ for here-strings
curl -X POST https://api.example.com/data -d @'
{
  "name": "John",
  "email": "john@example.com"
}
'@
```

### Bash/Zsh (Unix/Linux/macOS)
```bash
# Single quotes (most common in tutorials)
curl -X POST 'https://api.example.com/data' \
     -H 'Content-Type: application/json' \
     -d '{"name":"John"}'

# Double quotes with escaping
curl -X POST "https://api.example.com/data" \
     -H "Content-Type: application/json" \
     -d "{\"name\":\"John\"}"

# Mixed quotes (very common)
curl -X POST "https://api.example.com/data" \
     -H 'Content-Type: application/json' \
     -d '{"name":"John"}'
```

### macOS specific
```bash
# macOS often includes -g flag for globbing
curl -g -X POST 'https://api.example.com/[data]'

# macOS Terminal often has smart quotes (from copy-paste)
curl -X POST 'https://api.example.com/data' # Note: these might be smart quotes
```

## Real Examples from Popular APIs

### Stripe (from their docs)
```bash
# Unix/Linux/macOS
curl https://api.stripe.com/v1/charges \
  -u sk_test_4eC39HqLyjWDarjtT1zdp7dc: \
  -d amount=2000 \
  -d currency=usd \
  -d source=tok_mastercard \
  -d description="My First Test Charge (created for API docs)"

# Windows Command Prompt
curl https://api.stripe.com/v1/charges ^
  -u sk_test_4eC39HqLyjWDarjtT1zdp7dc: ^
  -d amount=2000 ^
  -d currency=usd ^
  -d source=tok_mastercard ^
  -d description="My First Test Charge (created for API docs)"
```

### GitHub API (from their docs)
```bash
# With personal access token
curl -H "Authorization: token OAUTH-TOKEN" https://api.github.com/user/repos

# With Accept header
curl -H "Accept: application/vnd.github.v3+json" https://api.github.com/users/octocat/repos

# Creating a gist
curl -X POST -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/gists \
  -d '{"description":"Hello World Examples","public":true,"files":{"hello_world.rb":{"content":"puts \"Hello World\""}}}'
```

### AWS (from their docs)
```bash
# S3 with signature
curl -X PUT -T "file.txt" \
  -H "Host: my-bucket.s3.amazonaws.com" \
  -H "Date: Mon, 26 Sep 2022 12:00:00 GMT" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=..." \
  https://my-bucket.s3.amazonaws.com/file.txt

# EC2 DescribeInstances
curl "https://ec2.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15" \
  -H "Authorization: AWS4-HMAC-SHA256 ..."
```

### Elasticsearch
```bash
# Pretty common pattern
curl -X GET "localhost:9200/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match_all": {}
  }
}'

# With authentication
curl -u elastic:password -X GET "https://localhost:9200/_cluster/health?pretty"
```

### Docker Registry
```bash
# Login and get token
curl -u username:password "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull"

# Use token
curl -H "Authorization: Bearer TOKEN" https://registry-1.docker.io/v2/library/ubuntu/manifests/latest
```

### Kubernetes API
```bash
# With bearer token
curl -X GET https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  --header "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# With client cert
curl --cert client.crt --key client.key --cacert ca.crt \
  https://kubernetes-api-server:6443/api/v1/pods
```

### Common Patterns We Must Handle

1. **Line Continuations**
   - Unix/Mac: `\` (backslash)
   - Windows CMD: `^` (caret)
   - PowerShell: `` ` `` (backtick)

2. **Quote Styles**
   - Single quotes: `'value'`
   - Double quotes: `"value"`
   - Escaped quotes: `\"value\"`
   - No quotes: `value`
   - Smart quotes: `"value"` (from copy-paste)

3. **Data Input**
   - Inline: `-d '{"key":"value"}'`
   - From file: `-d @data.json`
   - Form data: `-F 'file=@upload.txt'`
   - Multiple -d: `-d key1=value1 -d key2=value2`

4. **Authentication Patterns**
   - Basic: `-u user:pass`
   - Bearer: `-H "Authorization: Bearer TOKEN"`
   - API Key: `-H "X-API-Key: key"`
   - AWS Signature: Complex Authorization headers

5. **Environment Variables**
   - Unix: `$TOKEN` or `${TOKEN}`
   - Windows: `%TOKEN%`
   - PowerShell: `$env:TOKEN`

6. **Output Control**
   - Silent: `-s`
   - Verbose: `-v`
   - Include headers: `-i`
   - Output to file: `-o file.txt`
   - Write-out: `-w "%{http_code}"`

7. **Special Characters**
   - URLs with brackets: `https://api.example.com/[id]`
   - URLs with spaces: `https://api.example.com/my%20file`
   - Data with special chars: `-d "message=Hello & goodbye"`

## Testing Code

```csharp
using CurlDotNet;
using System;
using System.Threading.Tasks;

public class CurlVariationTests
{
    public static async Task TestAllVariations()
    {
        // Test 1: Windows-style with double quotes and carets
        var windowsCmd = @"curl -X POST ""https://api.example.com/data"" ^
            -H ""Content-Type: application/json"" ^
            -d ""{\"name\":\"John\"}""";

        // Test 2: Unix-style with single quotes and backslashes
        var unixCmd = @"curl -X POST 'https://api.example.com/data' \
            -H 'Content-Type: application/json' \
            -d '{""name"":""John""}'";

        // Test 3: Mixed quotes (very common from copy-paste)
        var mixedCmd = @"curl -X POST ""https://api.example.com/data"" \
            -H 'Content-Type: application/json' \
            -d '{""name"":""John""}'";

        // Test 4: PowerShell style with backticks
        var powershellCmd = @"curl -X POST https://api.example.com/data `
            -H ""Content-Type: application/json"" `
            -d '{""name"":""John""}'";

        // Test 5: No quotes where possible
        var noQuotesCmd = "curl -X POST https://api.example.com/data -H Content-Type:application/json -d {name:John}";

        // Test 6: Multiple -d parameters
        var multiDataCmd = "curl -X POST https://api.example.com/data -d name=John -d email=john@example.com -d age=30";

        // Test 7: File upload
        var fileUploadCmd = @"curl -X POST https://api.example.com/upload -F 'file=@document.pdf' -F 'description=Important doc'";

        // Test 8: Complex authentication
        var authCmd = "curl -u myuser:mypass -X GET https://api.example.com/private";

        // Test 9: With environment variable references (should handle gracefully)
        var envVarCmd = "curl -H 'Authorization: Bearer $TOKEN' https://api.example.com/data";

        // Test 10: Smart quotes (from copy-paste)
        var smartQuotesCmd = "curl -X POST "https://api.example.com/data" -H "Content-Type: application/json"";

        // All should work
        try
        {
            Console.WriteLine("Testing Windows style...");
            var r1 = await Curl.ExecuteAsync(windowsCmd);
            Console.WriteLine($"✓ Windows: {r1.StatusCode}");

            Console.WriteLine("Testing Unix style...");
            var r2 = await Curl.ExecuteAsync(unixCmd);
            Console.WriteLine($"✓ Unix: {r2.StatusCode}");

            Console.WriteLine("Testing mixed quotes...");
            var r3 = await Curl.ExecuteAsync(mixedCmd);
            Console.WriteLine($"✓ Mixed: {r3.StatusCode}");

            Console.WriteLine("Testing PowerShell style...");
            var r4 = await Curl.ExecuteAsync(powershellCmd);
            Console.WriteLine($"✓ PowerShell: {r4.StatusCode}");

            Console.WriteLine("Testing no quotes...");
            var r5 = await Curl.ExecuteAsync(noQuotesCmd);
            Console.WriteLine($"✓ No quotes: {r5.StatusCode}");

            Console.WriteLine("Testing multiple -d...");
            var r6 = await Curl.ExecuteAsync(multiDataCmd);
            Console.WriteLine($"✓ Multi-data: {r6.StatusCode}");

            Console.WriteLine("Testing file upload...");
            var r7 = await Curl.ExecuteAsync(fileUploadCmd);
            Console.WriteLine($"✓ File upload: {r7.StatusCode}");

            Console.WriteLine("Testing authentication...");
            var r8 = await Curl.ExecuteAsync(authCmd);
            Console.WriteLine($"✓ Auth: {r8.StatusCode}");

            Console.WriteLine("Testing env variables...");
            var r9 = await Curl.ExecuteAsync(envVarCmd);
            Console.WriteLine($"✓ Env vars: {r9.StatusCode}");

            Console.WriteLine("Testing smart quotes...");
            var r10 = await Curl.ExecuteAsync(smartQuotesCmd);
            Console.WriteLine($"✓ Smart quotes: {r10.StatusCode}");

            Console.WriteLine("\n✅ All variations handled successfully!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed: {ex.Message}");
        }
    }
}
```

## Key Parser Requirements

The CommandParser must handle:

1. **Quote normalization**
   - Convert smart quotes to regular quotes
   - Handle escaped quotes inside quoted strings
   - Support single, double, and no quotes

2. **Line continuation removal**
   - Remove `\` (Unix/Linux/Mac)
   - Remove `^` (Windows CMD)
   - Remove `` ` `` (PowerShell)
   - Preserve line breaks inside quoted strings

3. **Environment variable detection**
   - Warn when `$VAR` or `%VAR%` detected
   - Option to provide replacements
   - Or leave as-is for server to handle

4. **Multiple data handling**
   - Combine multiple `-d` into single payload
   - Handle both form-encoded and JSON
   - Support `-d @filename` for file input

5. **Platform detection**
   - Auto-detect quote style
   - Auto-detect line continuation style
   - Provide hints for better parsing