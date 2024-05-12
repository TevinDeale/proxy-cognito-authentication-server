const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const axios = require("axios");
const winston = require("winston")
const { format } = require("winston")
const dotenv = require("dotenv")
dotenv.config()

//Variables
const env = process.env
const environment = env.NODE_ENV
const PORT = env.PORT
const HOST = env.HOST
const API_SERVICE_URL = env.API_SERVICE_URL
const FRONT_END_URL = env.FRONT_END_URL
const secret = env.COGNITO_SECRET
const clientId = env.COGNITO_ID
const userPoolId = env.USER_POOL_ID
const region = env.AWS_REGION
const dynamoDBSessionTableName = env.SESSION_TABLE_NAME
// End of Variables

//Logging setup
const options = {
  file: {
      level: 'info',
      filename: 'proxy.log',
      handleExceptions: true,
      maxsize: 5242880, // 5MB
      maxFiles: 15,
  },
  console: {
      level: 'verbose',
      timestamp: true,
      handleExceptions: true,
  },
};

const logger = winston.createLogger({
  format: winston.format.combine(format.timestamp(), format.splat(),format.simple()),
  transports: [new winston.transports.File(options.file)]
})

if (environment !== 'production') {
  logger.add(new winston.transports.Console(options.console))
}
//End of Logger setup

logger.verbose('Proxy starting')
logger.verbose(`Environment: ${environment}`)
logger.verbose(`Proxy port: ${PORT}`)
logger.verbose(`Proxy host: ${HOST}`)
logger.verbose(`API URL: ${API_SERVICE_URL}`)
logger.verbose(`Vue URL: ${FRONT_END_URL}`)
logger.verbose(`User Cognito secret: ${secret}`)
logger.verbose(`User Cognito clientID: ${clientId}`)
logger.verbose(`UserPoolID: ${userPoolId}`)
logger.verbose(`Current AWS Region: ${region}`)

// App setup
logger.info('Setting up express app')
const app = express();

logger.info('Setting Session Options')
let sessionOptions = {
  secret: env.COGNITO_SECRET,
  cookie: { maxAge: 60000000 },
  rolling: false,
  saveUninitialized: false,
  resave: false
}

logger.info('Checking environment to set secure cookies or not')
if (environment === 'production') {
  sessionOptions.cookie.secure = true
}

app.use(
  session(sessionOptions)
);

app.use(cookieParser());

app.use(
  cors({
    origin: env.FRONT_END_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  })
);
app.use(express.json());
logger.info('Express app setup complete')
// End of App setup

//Validate session method
const validateSession = async (req) => {
  logger.info('Validating Session')
  const signedSessionId = req.cookies["connect.sid"];
  const sessionid = cookieParser.signedCookie(signedSessionId, secret);
  logger.info(`SessionID from cookie: ${sessionid}`)
  let isValidated = false
  const response = await getSessionFromDDB(sessionid)

  if (response) {
    logger.info(`SessionID in session store: ${objectToString(response.sessionID.S)}`)
    req.headers["Authorization"] = `Bearer ${response.accessToken.S}`
    logger.verbose(`Access Token: ${objectToString(response.accessToken.S)}`)
    isValidated = true;
    logger.info('User was validated')
    return {isValidated: isValidated, req: req}
  } else {
    logger.warn('User was not validated: SessionID not valid')
    return isValidated
  }
};
// End

//API MIDDLEWARE
app.post("/login", async (req, res, next) => {
  logger.info('Running login API')
  logger.info(`Request Body: ${objectToString(req.body)}`)
  logger.info(`SessionID: ${objectToString(req.sessionID)}`)
  const { username, password } = req.body;

  logger.info('Calling signIn method')
  let token = await signIn(username, password);

  logger.info('Checking if token exists')
  if (token !== undefined) {
    logger.info('Token is present')
    const uuid = jwt.decode(token.itoken)['sub'];
    const exp = jwt.decode(token.atoken)['exp']
    logger.info(`uuid: ${uuid}`);
    logger.info('Adding tokens to session store')
    const session = await addSessionToDDB(req.sessionID, token.itoken, token.itoken, token.rtoken, uuid, exp)
    if (session === true) {
      req.session.authenticated = true;
      req.session.user = {
        username,
      };
      req.session.uuid = uuid;
      logger.info('Login successful')
      res.status(200).json({ msg: "Successful Login"});
    } else {
      logger.warn('User was authenticated, but session was not created successfully')
      req.session.authenticated = false
      res.status(500).json({msg: "A session error occurred"})
    }
  } else {
    logger.warn('User was not authenticated: Bad Credentials')
    req.session.authenticated = false;
    res.status(401).json({ msg: "Bad Credentials" });
  }
});

app.get("/signout", (req, res) => {
  logger.info('Running signout API')
  logger.info('Destroying session')
  req.session.destroy((err) => {
    if (err) {
      logger.error(`There was a error destroying session: ${err}`)
      return res.status(500);
    }

    logger.info('Clearing cookies')
    res.clearCookie("connect.sid");
    res.clearCookie("idtoken");
    res.header("Access-Control-Allow-Origin", FRONT_END_URL);
    res.header("Access-Control-Allow-Credentials", "true");
    logger.info('Running deleteSessionFromDDB')
    deleteSessionFromDDB(req.sessionID)
    logger.info('Session successfully destroyed')
    res.status(200);
  });
});

app.post("/signup", async (req, res) => {
  logger.info('Running signup API')
  logger.verbose(`Request body: ${objectToString(req.body)}`)
  const { username, password, fname, lname } = req.body;
  const response = await signUp(username, password, fname, lname);
  logger.verbose(`Sign up response: ${objectToString(response)}`)
  if (!response.success) {
    if (response.error.__type === "UsernameExistsException") {
      logger.warn('Username already exist')
      res.status(409).json({ msg: "Username already exists" });
    } else {
      logger.error('Error occurred while creating the user in Cognito')
      logger.error(`Error signing up: ${objectToString(response.error.__type)}`)
      logger.verbose(`Error: ${objectToString(response.error)}`)
      res
        .status(500)
        .json({ msg: "An error occurred while creating the user" });
    }
  } else {
    logger.info('User was added to Cognito')
    logger.info('Adding user to DB')
    const success = await addUserToDB(username, fname, lname, response.uuid);
    if (success) {
      logger.info('User was added to DB')
      res.status(201).json({ msg: "User created and added to database" });
    } else {
      logger.info('Error adding user to DB')
      logger.info('Removing user from Cognito')
      adminDeleteUser(username);
      res.status(500).json({ msg: "Error while creating user in DB" });
    }
  }
}); 

logger.info('Middleware starting')
app.use(
  "", async (req, res, next) => {
    logger.info('Request has entered the middleware')
    if (req.path === "/home") {
        logger.info('Bypassing session validation')
      next();
    } else {
      const response = await validateSession(req, res);
      if (response.isValidated) {
        next()
      } else {
        res.status(403).json({ msg: "Invalid Session ID" });
      }
    }
  },
  createProxyMiddleware({
    logger,
    target: API_SERVICE_URL,
    changeOrigin: true,
    on: {
        proxyReq: (proxyReq, req, res) => {
            logger.info(`Body of req going to proxy: ${objectToString(req.body)}`);
            proxyReq.setHeader('authorization',req.headers['Authorization'])
            proxyReq.write(JSON.stringify(req.body))
        }
    }
    })
);


app.listen(PORT, HOST, () => {
  logger.info(`Starting Proxy at ${HOST}:${PORT}`);
});
// END API MIDDLEWARE

//AWS Cognito SDK METHODS
const {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  AdminDeleteUserCommand,
} = require("@aws-sdk/client-cognito-identity-provider");
const client = new CognitoIdentityProviderClient({ region: region, logger: logger });

const signIn = async (username, password) => {
  logger.info('Starting sign-in method')
  logger.info(`Username: ${username}`)
  try {
    logger.info('Generating hash')
    const message = username + clientId;
    logger.verbose(`Message to hash: ${message}`)
    const secretHash = crypto.createHmac("sha256", secret);
    secretHash.update(message);

    const sh = secretHash.digest("base64");
    logger.info(`sh: ${sh}`);

    const input = {
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: {
        PASSWORD: password,
        SECRET_HASH: sh,
        USERNAME: username,
      },
      ClientId: clientId,
    };

    logger.info('Running Cognito auth command')
    const command = new InitiateAuthCommand(input);
    const response = await client.send(command);
    let atoken = response.AuthenticationResult.AccessToken;
    let itoken = response.AuthenticationResult.IdToken;
    let rtoken = response.AuthenticationResult.RefreshToken;
    let exp = response.AuthenticationResult.ExpiresIn;

    logger.verbose(`Access token: ${atoken}`)
    logger.verbose(`ID token: ${itoken}`)
    logger.verbose(`Refresh Token: ${rtoken}`)
    logger.verbose(`Expiration(seconds): ${exp}`)

    logger.verbose(`Sign in response: ${objectToString(response)}`)
    logger.info('Sign in complete')
    return {
      atoken,
      itoken,
      rtoken,
      exp,
    };
  } catch (error) {
    logger.error(`Error signing in: ${objectToString(error)}`)
  }
};

const signUp = async (username, password, fname, lname) => {
  logger.info('Running Signup method')
  let success = false;
  try {
    const message = username + clientId;
    const secretHash = crypto.createHmac("sha256", secret);
    secretHash.update(message);

    const sh = secretHash.digest("base64");
    const input = {
      ClientId: clientId,
      Username: username,
      Password: password,
      SecretHash: sh,
      UserAttributes: [
        {
          Name: "given_name",
          Value: fname,
        },
        {
          Name: "family_name",
          Value: lname,
        },
      ],
    };
    logger.verbose(`Input: ${input}`)
    logger.info('Initiating sign up command')
    const command = new SignUpCommand(input);
    const response = await client.send(command);
    logger.verbose(objectToString(response))
    success = true
    return { success: success, uuid: response.UserSub };
  } catch (error) {
    logger.error(`There was a error signing up`)
    logger.verbose(objectToString(error))
    return { success: success, error: error };
  }
};

const clientAuth = async () => {
  logger.info('Running client auth method')
  const proxyClientId = env.PROXY_CLIENT_ID;
  const proxyClientSecret = env.PROXY_CLIENT_SECRET;
  const message = proxyClientId + ":" + proxyClientSecret;
  const buffer = Buffer.from(message);
  const base64 = buffer.toString("base64");

  try {
    logger.info('Fetching token from Cognito')
    const response = await axios({
      method: "post",
      url: env.COGNITO_AUTH_URL,
      headers: {
        Authorization: "Basic " + base64,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: "grant_type=client_credentials",
    });
    logger.info('Token fetching successful')
    logger.verbose(`Token: ${objectToString(response.data.access_token)}`)
    return response.data.access_token;
  } catch (error) {
    logger.error('Error fetching client token')
    logger.verbose(objectToString(error))
  }
};

const addUserToDB = async (username, fname, lname, uuid) => {
  logger.info('Running addUserToDB method')
  let success = true;
  try {
    logger.info('Fetching client token using clientAuth method')
    const token = await clientAuth();
    logger.info("starting to add user to db")
    logger.verbose(token)
    const response = await axios({
      method: "post",
      url: API_SERVICE_URL + "/api/customer/add",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",
      },
      data: {
        username: username,
        fname: fname,
        lname: lname,
        uuid: uuid,
      },
    });
    logger.info('User added to DB successfully')
    return success;
  } catch (error) {
    logger.error('adding user to the DB')
    success = false;
    return success;
  }
};

const adminDeleteUser = async (username) => {
  logger.info('Running adminDeleteUser method')
  try {
    const input = {
      UserPoolId: userPoolId,
      Username: username,
    };
    logger.verbose(`Input: ${objectToString(input)}`)
    logger.info('Initiating AdminDeleteUserCommand')
    const command = new AdminDeleteUserCommand(input);
    const response = await client.send(command);
    logger.verbose(objectToString(response))
    logger.info('User deleted')
  } catch (error) {
    logger.error('There was an error deleting user: ' + username)
    logger.verbose(objectToString(error))
  }
};
// END AWS Cognito SDK METHODS

// AWS DynamoDB SDK Methods
logger.info('Setting up DynamoDB SDK')
const { GetItemCommand, PutItemCommand, DynamoDBClient, DeleteItemCommand } = require("@aws-sdk/client-dynamodb");
const dynamodbClient = new DynamoDBClient({
  region: region,
  logger: logger,
})

const addSessionToDDB = async (sessionID, accessToken, idToken, refreshToken, uuid, exp) => {
  let success = false
  logger.info('Running addSessionToDBB')
  logger.verbose(`Input: SessionID: ${sessionID},accessToken: ${accessToken}, idTokne: ${idToken}, refreshToken: ${refreshToken}, uuid: ${uuid}, exp: ${exp}`)
  const input = {
    TableName: dynamoDBSessionTableName,
    ReturnConsumedCapacity: "TOTAL",
    Item: {
      "sessionID": {
        "S": sessionID
      },
      "accessToken": {
        "S": accessToken
      },
      "idToken": {
        "S": idToken
      },
      "refreshToken": {
        "S": refreshToken
      },
      "uuid": {
        "S": uuid
      },
      "sessionExp": {
        "N": exp.toString()
      }

    }
  }

  try {
    logger.info('Trying put item command')
    const command = new PutItemCommand(input)
    const response = await dynamodbClient.send(command)
    logger.info('Session successfully added to DynamoDB')
    logger.verbose(objectToString(response))
    success = true
    return success
  } catch(error) {
    logger.error('Error adding session to DynamoDB')
    logger.verbose(objectToString(error))
    return success
  }
}

const deleteSessionFromDDB = async (sessionID) => {
  let success = false
  logger.info('Running deleteSessionFromDBB')
  logger.verbose(`Input: SessionID: ${sessionID}`)
  const input = {
    TableName: dynamoDBSessionTableName,
    ReturnConsumedCapacity: "TOTAL",
    Key: {
      "sessionID": {
        "S": sessionID
      }
    }
  }

  try {
    logger.info('Trying delete session item command')
    const command = new DeleteItemCommand(input)
    const response = await dynamodbClient.send(command)
    logger.info('Session successfully deleted from DynamoDB')
    logger.verbose(objectToString(response))
    success = true
    return success
  } catch(error) {
    logger.error('Error deleting session from DynamoDB')
    logger.verbose(objectToString(error))
    return success
  }
}

const getSessionFromDDB = async (sessionID) => {
  logger.info('Running getSessionFromDDB')
  let success = false
  const input = {
    TableName: dynamoDBSessionTableName,
    ReturnConsumedCapacity: "TOTAL",
    Key: {
      "sessionID": {
        "S": sessionID
      }
    }
  }

  try {
    logger.info(`Getting session: ${sessionID}`)
    const command = new GetItemCommand(input)
    const response = await dynamodbClient.send(command)
    logger.info('Session successfully retrieved')
    const item = response.Item
    success = true
    return item
  } catch(error) {
    logger.error('Getting item from DynamoDB')
    logger.error(objectToString(error))
    return success
  }
}
//END AWS DynamoDB SDK Methods

//Helper Methods
const objectToString = (object) => {
  const objectString = JSON.stringify(object)
  return objectString
}
//End of Helper Methods

//CLEANUP METHODS
const cleanUpUsers = async (users) => {
  logger.info('Running cleanUpUsers')
    users.forEach(async (user) => {
        try {
            await adminDeleteUser(user);
            logger.info(`Deleted user: ${user}`);
        } catch (error) {
            logger.error(`Error deleteing user ${user}`)
            logger.verbose(error)
        }
    })
}
//END OF CLEANUP

