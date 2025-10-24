# Testing Real DigitalOcean API Documentation Examples

## From DigitalOcean's Official API Docs

### Create a Droplet (from their docs)
```bash
# Original from DigitalOcean docs
curl -X POST "https://api.digitalocean.com/v2/droplets" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"example.com","region":"nyc3","size":"s-1vcpu-1gb","image":"ubuntu-20-04-x64"}'
```

### CurlDotNet Implementation
```csharp
// This should just work by pasting:
var response = await Curl.ExecuteAsync(@"
    curl -X POST 'https://api.digitalocean.com/v2/droplets'
    -H 'Authorization: Bearer YOUR_TOKEN_HERE'
    -H 'Content-Type: application/json'
    -d '{""name"":""example.com"",""region"":""nyc3"",""size"":""s-1vcpu-1gb"",""image"":""ubuntu-20-04-x64""}'
");

// Parse the response
var droplet = response.ParseJson<DropletResponse>();
Console.WriteLine($"Droplet created: {droplet.Id}");
```

### List All Droplets
```bash
# From DigitalOcean
curl -X GET "https://api.digitalocean.com/v2/droplets" \
     -H "Authorization: Bearer $TOKEN"
```

```csharp
// In CurlDotNet
var droplets = await Curl.ExecuteAsync("curl -X GET 'https://api.digitalocean.com/v2/droplets' -H 'Authorization: Bearer YOUR_TOKEN'");
```

### Create SSH Key
```bash
# From DigitalOcean
curl -X POST "https://api.digitalocean.com/v2/account/keys" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"My SSH Public Key","public_key":"ssh-rsa AAAAB3NzaC1yc2..."}'
```

### Delete a Droplet
```bash
# From DigitalOcean
curl -X DELETE "https://api.digitalocean.com/v2/droplets/3164494" \
     -H "Authorization: Bearer $TOKEN"
```

## From AWS Documentation

### S3 List Buckets
```bash
# From AWS docs
curl "https://s3.amazonaws.com/" \
     -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=..."
```

### EC2 Describe Instances
```bash
# From AWS docs
curl "https://ec2.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15" \
     -H "Authorization: AWS4-HMAC-SHA256 ..."
```

## From Cloudflare Documentation

### List DNS Records
```bash
# From Cloudflare docs
curl -X GET "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records" \
     -H "X-Auth-Email: user@example.com" \
     -H "X-Auth-Key: c2547eb745079dac9320b638f5e225cf483cc5cfdda41" \
     -H "Content-Type: application/json"
```

### Create DNS Record
```bash
# From Cloudflare docs
curl -X POST "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records" \
     -H "X-Auth-Email: user@example.com" \
     -H "X-Auth-Key: c2547eb745079dac9320b638f5e225cf483cc5cfdda41" \
     -H "Content-Type: application/json" \
     -d '{"type":"A","name":"example.com","content":"198.51.100.4","ttl":3600}'
```

## From Linode Documentation

### Create Linode Instance
```bash
# From Linode docs
curl -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -X POST -d '{
       "image": "linode/debian10",
       "region": "us-east",
       "type": "g6-standard-2",
       "label": "my-linode",
       "root_pass": "aComplexP@ssword"
     }' \
     https://api.linode.com/v4/linode/instances
```

## From Heroku Documentation

### Deploy with Git
```bash
# Heroku uses git, but also has API
curl -X POST https://api.heroku.com/apps \
     -H "Accept: application/vnd.heroku+json; version=3" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"my-app-name"}'
```

## Common Patterns Across All Providers

1. **Authentication Headers**
   - Bearer tokens: `-H "Authorization: Bearer TOKEN"`
   - API keys: `-H "X-API-Key: KEY"`
   - Basic auth: `-u username:password`

2. **JSON Payloads**
   - Always with: `-H "Content-Type: application/json"`
   - Complex nested JSON structures
   - Arrays and objects

3. **HTTP Methods**
   - GET for listing
   - POST for creating
   - PUT/PATCH for updating
   - DELETE for removing

4. **Response Handling**
   - Usually JSON responses
   - Status codes matter
   - Rate limit headers

## What CurlDotNet Must Handle Correctly

✅ **Line continuations** with `\`
✅ **Environment variables** like `$TOKEN`
✅ **Complex JSON** with nested structures
✅ **Multiple headers**
✅ **Various auth methods**
✅ **Different HTTP methods**
✅ **Query parameters**
✅ **Response parsing**

## Test Code for All Examples

```csharp
public async Task TestRealProviderExamples()
{
    // DigitalOcean - Create Droplet
    var doCreate = await Curl.ExecuteAsync(@"
        curl -X POST 'https://api.digitalocean.com/v2/droplets'
        -H 'Authorization: Bearer YOUR_TOKEN'
        -H 'Content-Type: application/json'
        -d '{""name"":""test.com"",""region"":""nyc3"",""size"":""s-1vcpu-1gb"",""image"":""ubuntu-20-04-x64""}'
    ");

    // AWS S3 - List Buckets
    var awsS3 = await Curl.ExecuteAsync(@"
        curl 'https://s3.amazonaws.com/'
        -H 'Authorization: AWS4-HMAC-SHA256 Credential=KEY/20130524/us-east-1/s3/aws4_request'
    ");

    // Cloudflare - Create DNS
    var cfDns = await Curl.ExecuteAsync(@"
        curl -X POST 'https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records'
        -H 'X-Auth-Email: user@example.com'
        -H 'X-Auth-Key: API_KEY'
        -H 'Content-Type: application/json'
        -d '{""type"":""A"",""name"":""example.com"",""content"":""198.51.100.4""}'
    ");

    // All should parse correctly
    Assert.IsNotNull(doCreate);
    Assert.IsNotNull(awsS3);
    Assert.IsNotNull(cfDns);
}
```