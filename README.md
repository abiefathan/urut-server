# JSONServer + JWT Auth
Json JWT UNTUK URUT/PIJAT


A Fake REST API URUT AJA ! using json-server with JWT authentication. 

Implemented End-points: login,register

## Install

```bash
$ npm install
$ npm run start-urut
```

Might need to run
```
npm audit fix
```

## How to login/register?

BUAT ENDPOINT LOGINNYA YANG INI

```
POST http://localhost:8000/auth/login
POST http://localhost:8000/auth/register
```
with the following data 

```
{
  "email": "abiefathan22@gmail.com",
  "password": "abiabi",
}
```

You should receive an access token with the following format 

```
{
   "access_token": "<ACCESS_TOKEN>"
}
```


You should send this authorization with any request to the protected endpoints

```
Authorization: Bearer <ACCESS_TOKEN>
```




