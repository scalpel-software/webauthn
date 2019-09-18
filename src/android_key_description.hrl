%% Generated by the Erlang ASN.1 compiler. Version: 5.0.9
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition in module AndroidKeyDescription.

-ifndef(_ANDROID_KEY_DESCRIPTION_HRL_).
-define(_ANDROID_KEY_DESCRIPTION_HRL_, true).

-record('AndroidKeyDescription', {
  keymasterVersion,
  attestationChallenge,
  softwareEnforced,
  teeEnforced,
  uniqueId = asn1_NOVALUE
}).

-record('AuthorizationList', {
  purpose = asn1_NOVALUE,
  algorithm = asn1_NOVALUE,
  keySize = asn1_NOVALUE,
  blockMode = asn1_NOVALUE,
  digest = asn1_NOVALUE,
  padding = asn1_NOVALUE,
  callerNonce = asn1_NOVALUE,
  minMacLength = asn1_NOVALUE,
  kdf = asn1_NOVALUE,
  ecCurve = asn1_NOVALUE,
  rsaPublicExponent = asn1_NOVALUE,
  eciesSingleHashMode = asn1_NOVALUE,
  includeUniqueId = asn1_NOVALUE,
  blobUsageRequirement = asn1_NOVALUE,
  bootloaderOnly = asn1_NOVALUE,
  activeDateTime = asn1_NOVALUE,
  originationExpireDateTime = asn1_NOVALUE,
  usageExpireDateTime = asn1_NOVALUE,
  minSecondsBetweenOps = asn1_NOVALUE,
  maxUsesPerBoot = asn1_NOVALUE,
  noAuthRequired = asn1_NOVALUE,
  userAuthType = asn1_NOVALUE,
  authTimeout = asn1_NOVALUE,
  allApplications = asn1_NOVALUE,
  applicationId = asn1_NOVALUE,
  applicationData = asn1_NOVALUE,
  creationDateTime = asn1_NOVALUE,
  origin = asn1_NOVALUE,
  rollbackResistant = asn1_NOVALUE,
  rootOfTrust = asn1_NOVALUE,
  osVersion = asn1_NOVALUE,
  patchLevel = asn1_NOVALUE,
  uniqueId = asn1_NOVALUE
}).

-record('RootOfTrust', {
  verifiedBootKey,
  osVersion,
  patchMonthYear
}).

-endif. %% _ANDROID_KEY_DESCRIPTION_HRL_
