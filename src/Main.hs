{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
import Crypto.BCrypt
import Data.Aeson.TH (defaultOptions, deriveJSON)
import qualified Data.ByteString as T
import Data.Maybe (fromMaybe)
import Data.Text
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Database.Persist as Persist hiding (get)
import Database.Persist.Sqlite hiding (get, insert)
import Database.Persist.TH
import GHC.Generics
import qualified GHC.TypeError as Data
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
|]

data Credentials = Credentials {credUsername :: Text, credPassword :: Text} deriving (Generic, Show)

data SimpleUser = SimpleUser {name :: Text, email :: Text, password :: Text} deriving (Generic, Show)

$(deriveJSON defaultOptions ''Credentials)
$(deriveJSON defaultOptions ''SimpleUser)

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
      Right id -> do
        result <- deleteUser id
        case result of
          Left err -> setStatus status404 >> text err
          Right _ -> setStatus status200 >> text "Hooray!"

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

verifyJwt :: Text -> Maybe (JWT VerifiedJWT)
verifyJwt inp =
  case decode inp of
    Nothing -> Nothing
    Just uJWT -> verify (toVerify $ hmacSecret secretKey) =<< Just uJWT

-- case fmap claims token of
--             Nothing -> return $ Left "Unauthorized"
--             Just ans ->
--               case sub ans of
--                 Nothing -> return $ Left "Unauthorized"
--                 Just ansT -> return $

-- jwtMiddleware :: ApiAction () -> ApiAction ()
-- jwtMiddleware action = do
--   maybeToken <- Web.header "Authorization"
--   case maybeToken of
--     Nothing -> unauthorized
--     Just token -> do
--       let tokenStr = fromMaybe "" $ Data.Text.stripPrefix "Bearer " token
--       case Jwt.decodeCompact $ LBS.fromStrict $ encodeUtf8 tokenStr of
--         Left _ -> unauthorized
--         Right jwt -> do
--           let verificationKey = undefined -- Your verification key
--           case Jws.verify Jwa.RS256 verificationKey jwt of
--             Left _ -> unauthorized
--             Right _ -> action
--   where
--     unauthorized = Spock.setStatus Spock.status401 >> Spock.json ("Unauthorized" :: T.Text)

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
deleteUser id =
  return $ Left id

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

-- TODO validate token

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
