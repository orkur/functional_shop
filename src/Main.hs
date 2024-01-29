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
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Database.Persist as Persist hiding (get)
import Database.Persist.Sqlite hiding (get, insert)
import Database.Persist.TH
import Network.HTTP.Types.Status
import Web.Spock as Web
import Web.Spock.Config (PoolOrConn (PCPool), defaultSpockCfg)

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
    newUser <- jsonBody' :: ApiAction (Maybe User)
    case newUser of
      Nothing ->
        setStatus status400 >> text "Non valid user"
      Just user -> do
        result <- registerUser user
        case result of
          Left err -> setStatus status400 >> text err
          Right _ -> setStatus status200 >> text "registered"
  get "users" $ do
    allPeople <- runSQL $ selectList [] [Asc UserId]
    json allPeople

-- get

registerUser :: User -> ApiAction (Either Text ())
registerUser user = do
  userExists <- isNameExists (userName user)
  mailExists <- isEmailExists (userEmail user)
  hashedPassword <- hashPassword' (userPassword user)
  case (userExists, mailExists, hashedPassword) of
    (True, _, _) -> return $ Left "User with this username exists!"
    (_, True, _) -> return $ Left "User with this Mail exists!"
    (_, _, Nothing) -> return $ Left "there's problem with password, please use latin characters!"
    (_, _, Just pass) -> runSQL (insert (User (userName user) (userEmail user) pass False)) >> return (Right ())

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
hashPassword' password = do
  hashedPassword <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (encodeUtf8 password)
  case hashedPassword of
    Just pass -> return $ Just (decodeUtf8 pass)
    Nothing -> return Nothing

runSQL ::
  (HasSpock m, SpockConn m ~ SqlBackend) =>
  SqlPersistT (LoggingT IO) a ->
  m a
runSQL action = runQuery $ \conn -> runStdoutLoggingT $ runSqlConn action conn
