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

import Control.Monad.Logger (LoggingT, runStdoutLoggingT)
import Data.Aeson (KeyValue ((.=)), Value (String), object)
import Data.Text (Text)
import Database.Persist as Persist hiding (get)
import Database.Persist.Sql (delete)
import Database.Persist.Sqlite hiding (get)
import Database.Persist.TH
import Network.HTTP.Types.Status (status400)
import Web.Spock as Web
import Web.Spock.Config (PoolOrConn (PCPool), defaultSpockCfg)

share
  [mkPersist sqlSettings, mkMigrate "migrateAll"]
  [persistLowerCase|
Person json -- The json keyword will make Persistent generate sensible ToJSON and FromJSON instances for us.
  name Text
  age Int
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
  get "people" $ do
    allPeople <- runSQL $ selectList [] [Asc PersonId]
    json allPeople
  post "people" $ do
    maybePerson <- jsonBody' :: ApiAction (Maybe Person)
    case maybePerson of
      Nothing -> do
        setStatus status400
        text "Bad request!"
      Just thePerson -> do
        newId <- runSQL $ insert thePerson
        json $ object ["result" .= String "success", "id" .= newId]
  Web.delete "people" $ do
    maybePersonId <- param "id" :: ApiAction (Maybe PersonId)
    case maybePersonId of
      Nothing -> errorJson 1 "Person ID not provided"
      Just personId -> do
        runSQL $ Database.Persist.Sql.delete personId
        json $ object ["result" .= String "success"]

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