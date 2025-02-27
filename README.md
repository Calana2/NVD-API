# NVD-API
National Vulnerability Database API Client, under development

`This product uses data from the NVD API but is not endorsed or certified by the NVD.`

### API KEY
- The public rate limit (without an API key) is 5 requests in a rolling 30-second window; the rate limit with an API key is 50 requests in a rolling 30-second window. More information here: https://nvd.nist.gov/developers/request-an-api-key
- If you are going to use an API key, create a .env file and add the following line:
``` env
 API_KEY="yourAPIKEY"
```

### Install
``` bash
go build -o nvd-search main.go
```

### Usage
``` bash
nvd-search --cve-id=CVE_ID
```
