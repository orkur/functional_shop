{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

module Main where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (LoggingT, runStdoutLoggingT)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT))
import Crypto.BCrypt
import Data.Aeson.TH (defaultOptions, deriveJSON)
import Data.Text
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time (UTCTime, getCurrentTime)
import Database.Persist as Persist hiding (get)
import Database.Persist.Sqlite as Sqlite hiding (delete, get, insert)
import Database.Persist.TH
import GHC.Generics
import GHC.Int (Int64)
import Network.HTTP.Types.Status
import Web.JWT
import Web.Spock as Web
import Web.Spock.Config (PoolOrConn (PCPool), defaultSpockCfg)
import Prelude hiding (exp)

secretKey :: Text
secretKey = "SŁOWA"

issuer :: Text
issuer = "localhost:8080"

share
  [mkPersist sqlSettings, mkMigrate "migrateAll"]
  [persistLowerCase|
User json
    name Text
    email Text
    password Text
    isAdmin Bool
    deriving Show
Blog json
    title Text
    content Text 
    authorId UserId Maybe
    publicationDate UTCTime
Tags json
    name Text 
    blog BlogId
|]

data Credentials = Credentials {credUsername :: Text, credPassword :: Text} deriving (Generic, Show)

data SimpleUser = SimpleUser {name :: Text, email :: Text, password :: Text} deriving (Generic, Show)

data ChangePassword = ChangePassword {oldPassword :: Text, newPassword :: Text} deriving (Generic, Show)

data SimpleBlog = SimpleBlog {title :: Text, content :: Text} deriving (Generic, Show)

$(deriveJSON defaultOptions ''Credentials)
$(deriveJSON defaultOptions ''SimpleUser)
$(deriveJSON defaultOptions ''ChangePassword)
$(deriveJSON defaultOptions ''SimpleBlog)

type Api = SpockM SqlBackend () () ()

type ApiAction a = SpockAction SqlBackend () () a

main :: IO ()
main = do
  pool <- runStdoutLoggingT $ createSqlitePool "api.db" 5
  spockCfg <- defaultSpockCfg () (PCPool pool) ()
  runStdoutLoggingT $ runSqlPool (do runMigration migrateAll) pool
  runSpock 8080 (spock spockCfg app)

app :: Api
app = do
  post "register" $ do
    newUser <- jsonBody' :: ApiAction (Maybe SimpleUser)
    case newUser of
      Nothing ->
        setStatus status400 >> text "Invalid user"
      Just simple -> do
        result <- registerUser simple
        case result of
          Left err -> setStatus status400 >> text err
          Right _ -> setStatus status200 >> text "registered"
  get "users" $ do
    allPeople <- runSQL $ selectList [] [Asc UserId]
    json allPeople
  post "login" $ do
    loginData <- jsonBody' :: ApiAction (Maybe Credentials)
    case loginData of
      Nothing -> setStatus status400 >> text "Invalid login data"
      Just login -> do
        result <- loginUser (credUsername login) (credPassword login)
        case result of
          Left err -> setStatus status400 >> text err
          Right token -> setStatus status200 >> liftIO token >>= json
  Web.delete "delete-account" $ do
    authenticate <- jwtMiddleware
    case authenticate of
      Left err -> setStatus status401 >> text err
      Right name -> do
        result <- deleteUser name
        case result of
          Left err -> setStatus status404 >> text err
          Right _ -> setStatus status200 >> text "User has been deleted!"
  put "change-password" $ do
    authenticate <- jwtMiddleware
    passwords <- jsonBody' :: ApiAction (Maybe ChangePassword)
    case (authenticate, passwords) of
      (Left err, _) -> setStatus status401 >> text err
      (_, Nothing) -> setStatus status400 >> text "Anvalid data"
      (Right name, Just pass) -> do
        result <- changePassword name pass
        case result of
          Left err -> setStatus status400 >> text err
          Right _ -> setStatus status200 >> text "password changed"
  post "post-blog" $ do
    newBlog <- jsonBody' :: ApiAction (Maybe SimpleBlog)
    time <- liftIO getCurrentTime
    userName <- jwtMiddleware
    case (newBlog, userName) of
      (Nothing, _) -> setStatus status400 >> text "Blog doesn't provided"
      (_, Left err) -> setStatus status401 >> text err
      (Just blog, Right name) -> do
        insertBlog blog time name >>= \case
          Left err -> setStatus status400 >> text err
          Right _ -> setStatus status200 >> text "Article added"

insertBlog :: SimpleBlog -> UTCTime -> Text -> ApiAction (Either Text ())
insertBlog blog time name = do
  id <- getUserId name
  case id of
    Left err -> return $ Left err
    Right number -> runSQL (insert (Blog (title blog) (content blog) (Just number) time)) >> return (Right ())

getUserId :: Text -> ApiAction (Either Text (Key User))
getUserId name = do
  user <- runSQL $ selectFirst [UserName ==. name] []
  case user of
    Nothing -> return $ Left "User does not exist"
    Just (Entity userId _) -> return $ Right userId

verifyJwt :: Text -> Maybe (JWT VerifiedJWT)
verifyJwt inp =
  case decode inp of
    Nothing -> Nothing
    Just uJWT -> verify (toVerify $ hmacSecret secretKey) =<< Just uJWT

loginUser :: Text -> Text -> ApiAction (Either Text (IO Text))
loginUser name pass = do
  user <- runSQL $ selectFirst [UserName ==. name] []
  case user of
    Nothing -> return $ Left "User with this username doesn't exist!"
    Just usr -> do
      if not (validatePassword (encodeUtf8 $ userPassword $ entityVal usr) (encodeUtf8 pass))
        then return $ Left "Wrong Password!"
        else return $ Right (generateJwtToken $ userName $ entityVal usr)

deleteUser :: Text -> ApiAction (Either Text ())
deleteUser name =
  -- this way only for improving skills :)
  isNameExists name
    >>= \x ->
      if not x
        then return $ Left "User doesn't exist"
        else runSQL (deleteWhere [UserName ==. name]) >> return (Right ())

changePassword :: Text -> ChangePassword -> ApiAction (Either Text ())
changePassword name pass = do
  user <- runSQL $ selectFirst [UserName ==. name] []
  hashedPassword <- hashPassword' (newPassword pass)
  case (user, hashedPassword) of
    (Nothing, _) -> return $ Left "User doesn't exist!"
    (_, Nothing) -> return $ Left "Hashing error!"
    (Just usr, Just correctPassword) -> do
      if not (validatePassword (encodeUtf8 $ userPassword $ entityVal usr) (encodeUtf8 $ oldPassword pass))
        then return $ Left "Wrong Password!"
        else runSQL $ updateWhere [UserName ==. name] [UserPassword =. correctPassword] >> return (Right ())

generateJwtToken :: Text -> IO Text
generateJwtToken username = do
  -- TODO expiration date maybe
  let cs =
        mempty
          { iss = stringOrURI issuer,
            sub = stringOrURI username
          } -- There is currently no verification of time related information (exp, nbf, iat).
      key = hmacSecret secretKey
   in return $ encodeSigned key mempty cs

jwtMiddleware :: ApiAction (Either Text Text)
jwtMiddleware = do
  maybeToken <- Web.header "Authorization"
  case maybeToken of
    Nothing -> return $ Left "Unauthorized: Missing authorization header"
    Just token -> do
      let bearer = Data.Text.stripPrefix "Bearer " token
      case bearer of
        Nothing -> return $ Left "Unauthorized: Missing bearer"
        Just tokenJWT ->
          case verifyJwt tokenJWT of
            Nothing -> return $ Left "Unauthorize: Invalid token"
            Just payload ->
              case sub $ claims payload of
                Nothing -> return $ Left "Unauthorized: Missing 'sub'"
                Just ansT -> return $ Right $ stringOrURIToText ansT

registerUser :: SimpleUser -> ApiAction (Either Text ())
registerUser user = do
  userExists <- isNameExists (name user)
  mailExists <- isEmailExists (email user)
  hashedPassword <- hashPassword' (password user)
  case (userExists, mailExists, hashedPassword) of
    (True, _, _) -> return $ Left "User with this username exists!"
    (_, True, _) -> return $ Left "User with this Mail exists!"
    (_, _, Nothing) -> return $ Left "there's problem with password, please use latin characters!"
    (_, _, Just pass) -> runSQL (insert (User (name user) (email user) pass False)) >> return (Right ())

isNameExists :: Text -> ApiAction Bool
isNameExists name = do
  existUser <- runSQL $ selectFirst [UserName ==. name] []
  case existUser of
    Just _ -> return True
    Nothing -> return False

isEmailExists :: Text -> ApiAction Bool
isEmailExists email = do
  existUser <- runSQL $ selectFirst [UserEmail ==. email] []
  case existUser of
    Just _ -> return True
    Nothing -> return False

hashPassword' :: Text -> ApiAction (Maybe Text)
hashPassword' pass = do
  hashedPassword <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (encodeUtf8 pass)
  case hashedPassword of
    Just passw -> return $ Just (decodeUtf8 passw)
    Nothing -> return Nothing

runSQL ::
  (HasSpock m, SpockConn m ~ SqlBackend) =>
  SqlPersistT (LoggingT IO) a ->
  m a
runSQL action = runQuery $ \conn -> runStdoutLoggingT $ runSqlConn action conn
