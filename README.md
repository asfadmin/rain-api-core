# rain-api-core

## Cookies
When logging in, rain-api-core sets a few cookies:

### asf-urs
asf-urs is a JWT cookie that contains various information about the logged in user. New development should use this cookie.

Its payload looks something like this:
```
{
  "urs-user-id": "<User's URS ID>",
  "urs-access-token": "<A URS access token string>",
  "urs-groups": [
    {
      "app_uid": "<UID of URS app>",
      "client_id": "<Client ID string>",
      "name": "<Name of group>"
    },
    {
      "app_uid": "<UID of URS app>",
      "client_id": "<Client ID string>",
      "name": "<Name of group>"
    },
  ],
  "iat": 1565294120,
  "exp: 1565299000
}

```

### urs-user-id
This contains the logged in user's URS user ID. 

### urs-access-token 
This contains the logged in user's URS access token. 