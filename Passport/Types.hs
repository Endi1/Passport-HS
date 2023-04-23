module Passport.Types (OAuthClientID, OAuthClientSecret, OAuthRedirectURI) where

import RIO (Text)
import URI.ByteString (Absolute, URIRef)

type OAuthClientID = Text

type OAuthClientSecret = Text

type OAuthRedirectURI = URIRef Absolute