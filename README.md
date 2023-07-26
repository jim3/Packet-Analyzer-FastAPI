### Packet Analyzer

Analyzes Wireshark network packets using Python and FastAPI to display the results in a web browser.

Pretty much the same app as the Node.js version except this uses Python and FastAPI. 

>Note: The app has only been tested to work on Linux (Ubuntu 22.04)

## Installation

Use `requirements.txt` to install the required packages.

```bash
pip install -r requirements.txt
```

## Usage

0. Capture some Wireshark packets and export them as a `.json` file.

1. Run the following command to start the server: `uvicorn app:app --reload`

2. Visit the upload page at `http://127.0.0.1:8000/` and upload your exported .json file.

3. The results will be displayed at the `/packets` endpoint.

## Example Output:

```json

{
    "ip": ["108.166.149.2", "152.199.4.33"],
    "mac": ["02:10:18:84:63:f3", "8c:dc:d4:38:0e:52"],
    "udp": ["58326", "37309", "53", "41177", "53487"],
    "tcp": ["57008", "443", "35116", "48718"],
    "iplocation": [
        {
            "ip": "108.166.149.2",
            "country_code": "US",
            "country_name": "United States of America",
            "region_name": "New York",
            "city_name": "New York City",
            "latitude": 41.353013,
            "longitude": -74.2637,
            "zip_code": "10918",
            "time_zone": "-04:00",
            "asn": "30036",
            "as": "Mediacom Communications Corp",
            "is_proxy": false
        },
        {
            "ip": "152.199.4.33",
            "country_code": "US",
            "country_name": "United States of America",
            "region_name": "California",
            "city_name": "Los Angeles",
            "latitude": 33.97207,
            "longitude": -118.43031,
            "zip_code": "90094",
            "time_zone": "-07:00",
            "asn": "15133",
            "as": "Edgecast Inc.",
            "is_proxy": false
        }
    ],
    "dns_query": [
        [
            ["mobile.events.data.microsoft.com", "api.ip2location.io"],
            [
                "mobile.events.data.microsoft.com",
                "onedscolprdcus01.centralus.cloudapp.azure.com",
                "mobile.events.data.trafficmanager.net",
                "api.ip2location.io"
            ]
        ]
    ],
    "dns_response": [
        [
            ["mobile.events.data.microsoft.com", "api.ip2location.io"],
            [
                "mobile.events.data.microsoft.com",
                "onedscolprdcus01.centralus.cloudapp.azure.com",
                "mobile.events.data.trafficmanager.net",
                "api.ip2location.io"
            ]
        ]
    ],
    "http_requests": []
}
```
