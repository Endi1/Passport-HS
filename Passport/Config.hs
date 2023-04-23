{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Passport.Config (auth0, authorizeUrl, auth0UserInfoUri, Auth0User (..)) where

import Data.Aeson (FromJSON)
import Network.OAuth.OAuth2 (OAuth2 (..), appendQueryParams, authorizationUrl)
import Passport.Types (OAuthClientID, OAuthClientSecret, OAuthRedirectURI)
import Passport.Utils (textToUri)
import RIO (Generic, Text)
import RIO.ByteString qualified as BS
import RIO.Text.Lazy qualified as TL
import URI.ByteString (URI)
import URI.ByteString.QQ (uri)

auth0 :: OAuthClientID -> OAuthClientSecret -> OAuthRedirectURI -> OAuth2
auth0 clientID clientSecret oauthRedirectUri =
  OAuth2
    { oauth2ClientId = clientID,
      oauth2ClientSecret = clientSecret,
      oauth2AuthorizeEndpoint = [uri|https://accounts.google.com/o/oauth2/v2/auth|],
      oauth2TokenEndpoint = [uri|https://www.googleapis.com/oauth2/v4/token|],
      oauth2RedirectUri = oauthRedirectUri
    }

authorizeUrl :: OAuthClientID -> OAuthClientSecret -> Text -> Maybe URI
authorizeUrl clientID clientSecret oauthRedirectUri =
  case textToUri oauthRedirectUri of
    Nothing -> Nothing
    Just u ->
      Just
        $ appendQueryParams
          [ ("scope", "openid profile email"),
            ("state", randomStateValue)
          ]
        $ authorizationUrl
        $ auth0 clientID clientSecret u

-- | TODO find better way to create @state@
-- which is recommended in <https://www.rfc-editor.org/rfc/rfc6749#section-10.12>
randomStateValue :: BS.ByteString
randomStateValue = "random-state-to-prevent-csrf"

-- | Endpoint for fetching user profile using access token
auth0UserInfoUri :: URI
auth0UserInfoUri = [uri|https://www.googleapis.com/oauth2/v3/userinfo|]

data Auth0User = Auth0User
  { name :: TL.Text,
    email :: TL.Text,
    sub :: TL.Text
  }
  deriving (Show, Generic)

instance FromJSON Auth0User