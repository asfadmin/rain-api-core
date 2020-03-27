# rain-api-core

## Cookies
When logging in, rain-api-core sets a few cookies:

### JWT cookie
The JWT cookie's name is set with the `JWT_COOKIENAME` env variable. If that variable goes unset, the default value is 'asf-urs'. 

#### Algorithim
JWT cookie uses RS256 by default. Optionally HS256

#### Keys
Keys for the JWT cookie are stored in AWS secret manager, fetched by name stored in the `JWT_KEY_SECRET_NAME` env var.


```json
{
  "rsa_priv_key": "verylongstring=",
  "rsa_pub_key": "longstring="
}
```

#### Payload
Its payload looks something like this:
```json
{
  "urs-user-id": "<User's URS ID>",
  "urs-access-token": "<A URS access token string>",
  "urs-groups": [
    {
      "app_uid": "<UID of URS app #1>",
      "client_id": "<Client ID string #1>",
      "name": "<Name of group #1>"
    },
    {
      "app_uid": "<UID of URS app #2>",
      "client_id": "<Client ID string #2>",
      "name": "<Name of group #2>"
    }
  ],
  "iat": 1565294120,
  "exp": 1565299000
}

```

