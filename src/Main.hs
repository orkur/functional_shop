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
import Control.Monad.Trans.Class (lift)
import Crypto.BCrypt (HashingPolicy (HashingPolicy), hashPassword, hashPasswordUsingPolicy, slowerBcryptHashingPolicy)
import qualified Crypto.BCrypt as BCrypt
import Data.Aeson (KeyValue ((.=)), Value (Bool, String), object)
import Data.ByteString.Char8 (pack)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Database.Persist (PersistQueryRead (selectFirst))
import Database.Persist as Persist hiding (get)
import Database.Persist.Sql (delete)
import Database.Persist.Sqlite hiding (get, insert)
import Database.Persist.TH
import Network.HTTP.Types.Status
import Web.Spock as Web
import Web.Spock.Action
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

registerUser :: User -> ApiAction (Either Text ())
registerUser user =
  if True
    then return $ Left "Error!"
    else return $ Right ()

-- registerUser :: User -> SqlPersistT (LoggingT IO) (Either Text ())
-- registerUser user = do
--   existsUser <- runSQL $ selectFirst [UserName ==. userName user] []
--   case existsUser of
--     Just _ -> return $ Left "User exists!"
--     Nothing -> do
--       existsMail <- runSQL $ selectFirst [UserEmail ==. userEmail user] []
--       case existsMail of
--         Just _ -> return $ Left "Mail exists!"
--         Nothing -> do
--           hashedPassword <- hashPassword' (userPassword user)
--           case hashedPassword of
--             Nothing -> lift $ return $ Left "there's problem with password, please use latin characters!"
--             Just existsPassword -> do
--               runSQL $ insert (User (userName user) (userEmail user) existsPassword False)
--               return $ Right ()

hashPassword' :: Text -> SqlPersistT (LoggingT IO) (Maybe Text)
hashPassword' password = do
  hashedPassword <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (encodeUtf8 password)
  return $ decodeUtf8 <$> hashedPassword

runSQL ::
  (HasSpock m, SpockConn m ~ SqlBackend) =>
  SqlPersistT (LoggingT IO) a ->
  m a
runSQL action = runQuery $ \conn -> runStdoutLoggingT $ runSqlConn action conn

errorJson :: Int -> Text -> ApiAction ()
errorJson code message =
  json $
    object
      [ "result" .= String "failure",
        "error" .= object ["code" .= code, "message" .= message]
      ]