# go-oidc-testapp

An OpenID Connect (OIDC) test application written in go. i
It is just a demo application which is using OpenID Connect Authorization Code Flow to authenticate users.
This simple test application is currently supporting this features:

* authentication using Google
* showing assets of OIDC authorization flow, like
    * accessToken
    * idToken
    * userInfo Service

## Dependencies

To compile the software you need to install this software first

* [Go](https://golang.org)
* make

## Building the software

```
make
```

## Running the software

starting the software
```
export OAUTH2_CLIENT_ID="YOURCLIENTID"
export OAUTH2_CLIENT_SECRET="YOURCLIENTSECRET"
./go-oidc-testapp
```

opening the application using your browser `http://localhost:9000`


## Further Information

* [OpenID Connect Specifications](https://openid.net/developers/specs/)
