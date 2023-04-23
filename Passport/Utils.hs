module Passport.Utils (textToUri) where

import Passport.Types (OAuthRedirectURI)
import RIO
import URI.ByteString (parseURI, strictURIParserOptions)

textToUri :: Text -> Maybe OAuthRedirectURI
textToUri uriText =
  case parseURI strictURIParserOptions $ encodeUtf8 uriText of
    Left _ -> Nothing
    Right u -> Just u