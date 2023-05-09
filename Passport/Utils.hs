{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Passport.Utils (textToUri, byteStringLazyToText, excepttToActionM, oauth2ErrorToText, paramValue, uriToText, generateToken) where

import Control.Exception (throw)
import Control.Monad.Trans.Except (ExceptT, runExceptT)
import Data.Aeson (Value (String))
import Data.ByteString.Lazy.Char8 qualified as BSL
import Network.OAuth.OAuth2 (OAuth2Error)
import Network.OAuth.OAuth2.TokenRequest (Errors)
import Passport.Types (OAuthRedirectURI)
import RIO (MonadIO (liftIO), Text, decodeUtf8', encodeUtf8)
import RIO.Map qualified as Map
import RIO.Text.Lazy qualified as TL
import URI.ByteString (URI, parseURI, serializeURIRef', strictURIParserOptions)
import Web.JWT (ClaimsMap (ClaimsMap), JWTClaimsSet (iss, unregisteredClaims), encodeSigned, hmacSecret, stringOrURI)
import Web.Scotty (ActionM, Param, raise)

textToUri :: Text -> Maybe OAuthRedirectURI
textToUri uriText =
  case parseURI strictURIParserOptions $ encodeUtf8 uriText of
    Left _ -> Nothing
    Right u -> Just u

uriToText :: URI -> TL.Text
uriToText u = case decodeUtf8' $ serializeURIRef' u of
  Left decodeErr -> throw decodeErr
  Right decodedURI -> TL.fromStrict decodedURI

byteStringLazyToText :: BSL.ByteString -> TL.Text
byteStringLazyToText = TL.pack . BSL.unpack

excepttToActionM :: ExceptT TL.Text IO a -> ActionM a
excepttToActionM e = do
  result <- liftIO $ runExceptT e
  either raise pure result

oauth2ErrorToText :: OAuth2Error Errors -> TL.Text
oauth2ErrorToText e = TL.pack $ "Unable fetch access token. error detail: " ++ show e

paramValue ::
  -- | Parameter key
  TL.Text ->
  -- | All parameters
  [Param] ->
  Either TL.Text TL.Text
paramValue key params =
  if null val
    then Left ("No value found for param: " <> key)
    else Right (head val)
  where
    val = snd <$> filter (hasParam key) params
    hasParam :: TL.Text -> Param -> Bool
    hasParam t = (== t) . fst

generateToken :: Text -> Text -> TL.Text -> TL.Text
generateToken secretKey issuer userEmail =
  TL.fromStrict $
    encodeSigned
      (hmacSecret secretKey)
      mempty
      mempty -- mempty returns a default JWTClaimsSet
        { iss = stringOrURI issuer,
          unregisteredClaims = ClaimsMap $ Map.fromList [("userEmail", String $ TL.toStrict userEmail)]
        }