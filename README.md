
# Proxy-Cognito Auth Server

Proxy server with AWS Cognito authentication built in. The sever was built on the ExpressJS framework using the [http-middleware-proxy](https://www.npmjs.com/package/http-proxy-middleware) package and [AWS SDK for JavaScript](https://aws.amazon.com/sdk-for-javascript/).


## Tech Stack

![My Skills](https://skillicons.dev/icons?i=js,nodejs,express,docker,aws,dynamodb,yarn)

## Features

- Authentication using AWS Cognito user pools
- Create or delete user from Cognito user pool
- Session management using DynamoDB
- Proxy API calls from UI to api endpoints
- Login, Sign up, and Sign out endpoints


## Requirements

Before deploying this sever, you will need to update the following enviroment variables. A example.env file has been created and the following values will need to be updated. Rename the file to ".env". Some of these enviroment variables require you to have an AWS account so that you can set up a dynamoDB table, and 2 Cognito user pools. 

```bash
  NODE_ENV = dev #dev or production
  PROXY_CLIENT_ID = #M2M Cognito Userpool CLIENT ID
  PROXY_CLIENT_SECRET = #M2M Cognito Userpool CLIENT SECRET
  PORT = 3000 #Port you want the proxy to listen on.
  HOST = localhost #If running in Docker use 0.0.0.0 here.
  API_SERVICE_URL = http://localhost:8080 #URL to the API
  FRONT_END_URL = http://localhost:5173 #URL to UI
  COGNITO_SECRET = #Cognito user pool client Secret
  COGNITO_ID = #Cognito User pool client ID
  USER_POOL_ID = #Cognito User pool ID
  AWS_REGION = #AWS Region
  COGNITO_AUTH_URL = #https://{###}.auth.us-east-1.amazoncognito.com/oauth2/token
  SESSION_TABLE_NAME = #DynamodDB table name
  AWSACCESSKEY = #AWS credentials
  AWSSECRETKEY = #AWS credentials
```
    
## Deployment

This project can be ran locally or in a Docker container. Clone the repository, create ".env" file, and run the following commands.

#### Docker

```bash
  docker build -t rocketbankproxy:dev --secret=type=file,id=.env,src=.env .
```
```bash
  docker run -p 5173:5173/tcp rocketbankproxy:dev .
```

#### Locally
Ensure that you have NodeJs and yarn installed.

```bash
  yarn install
```
```bash
  yarn start
```

## API Reference

#### Login

```http
  POST /login
```

| Parameter | Type     | 
| :-------- | :------- | 
| `username` | `string` |
| `password` | `string` |

Returns a JWT access token, identity token, and refresh token.

#### Sign Out

```http
  GET /signout
```

Destroys session and deletes the session details from the DynamoDB table.

#### Sign up

```http
  POST /signup
```

| Parameter | Type     | 
| :-------- | :------- | 
| `username` | `string` |
| `password` | `string` |
| `fname` | `string` |
| `lname` | `string` |

Creates a user in the AWS Cognito userpool and customer database. Returns a 201 status if successful. Returns a 409 status if username already exists. Returns a 500 status if there was a error in any process and reverts all changes.


## Contributing

Contributions are always welcome!

If you would like to contribute, reach out via X [@FiinnDev](https://x.com/FiinnDev)

