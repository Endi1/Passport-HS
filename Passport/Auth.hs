{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Passport.Auth (loginH, callbackH, signOutH) where

import Control.Monad.Trans.Except (ExceptT (ExceptT), withExceptT)
import Network.HTTP.Conduit (newManager, tlsManagerSettings)
import Network.HTTP.Types (status302, status500)
import Network.OAuth.OAuth2
  ( ExchangeToken (ExchangeToken),
    OAuth2Token (accessToken),
    authGetJSON,
    fetchAccessToken,
  )
import Passport.Config (Auth0User (email), auth0, auth0UserInfoUri, authorizeUrl)
import Passport.Utils (byteStringLazyToText, excepttToActionM, generateToken, oauth2ErrorToText, paramValue, textToUri, uriToText)

import RIO
  ( Text,
    liftIO,
    void,
  )
import RIO.Text (pack)
import RIO.Text.Lazy qualified as TL
import System.Environment (getEnv)
import Web.Scotty (ActionM, params, redirect, setHeader, status)
import Web.Scotty.Cookie (deleteCookie, setSimpleCookie)

-- | loginH is the function that starts the login process. It sends the request to the OAuth server to get the token
loginH :: ActionM ()
loginH = do
  oauthRedirectUri <- liftIO $ getEnv "OAUTH_REDIRECT_URI"
  clientID <- liftIO $ getEnv "OAUTH_CLIENT_ID"
  clientSecret <- liftIO $ getEnv "OAUTH_CLIENT_SECRET"

  case authorizeUrl (pack clientID) (pack clientSecret) (pack oauthRedirectUri) of
    Nothing -> status status500
    Just u -> do
      setHeader "Location" $ uriToText u
      status status302

-- | callbackH is the callback function called by the callback route.
-- It takes one argument which is a callback function that takes the user's email
-- as an argument and performs an IO operation. Usually it would be used to create a new row in a database.
callbackH :: (Text -> IO a) -> ActionM ()
callbackH authCallback = do
  oauthRedirectUri <- liftIO $ getEnv "OAUTH_REDIRECT_URI"
  secretToken <- liftIO $ pack <$> getEnv "SECRET_TOKEN"
  issuer <- liftIO $ pack <$> getEnv "ISSUER"
  pas <- params
  case textToUri $ pack oauthRedirectUri of
    Nothing -> status status500
    Just u -> do
      userEmail <- excepttToActionM $ do
        void $ ExceptT $ pure $ paramValue "state" pas
        codeP <- ExceptT $ pure $ paramValue "code" pas

        mgr <- liftIO $ newManager tlsManagerSettings

        -- Exchange authorization code for Access Token
        -- 'oauth2ErrorToText' turns (OAuth2 error) to Text which is the default way
        -- Scotty represents error message
        clientID <- liftIO $ pack <$> getEnv "OAUTH_CLIENT_ID"
        clientSecret <- liftIO $ pack <$> getEnv "OAUTH_CLIENT_SECRET"
        let code = ExchangeToken $ TL.toStrict codeP
        tokenResp <- withExceptT oauth2ErrorToText (fetchAccessToken mgr (auth0 clientID clientSecret u) code)

        -- Call API to resource server with Access Token being authentication code.
        -- 'byteStringLazyToText' exists for similar reason as 'oauth2ErrorToText'
        let at = accessToken tokenResp
        user <- withExceptT byteStringLazyToText (authGetJSON mgr at auth0UserInfoUri)

        _ <- liftIO $ authCallback (TL.toStrict $ email user)
        return (email user)

      setSimpleCookie "auth-token" $ TL.toStrict $ generateToken secretToken issuer userEmail
      redirect "/"

-- | The signOutH function is implemented by the route that would be called to sign out
signOutH :: ActionM ()
signOutH = do
  deleteCookie "auth-token"
  redirect "/"
