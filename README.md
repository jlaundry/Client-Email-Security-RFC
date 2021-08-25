---
title: Client-Email-Security
abbrev: TODO - Abbreviation
docname: draft-laundry-client-email-security
category: info

ipr: trust200902
area: General
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: J. Laundry
    name: Jed Laundry
    organization: CyberCX
    email: jed.laundry@cybercx.co.nz

normative:
  RFC2119:
  RFC2822:

informative:



--- abstract

This document proposes an email client security header, to move email security warnings from HTML inserted into the message into a standard header, making it easier for End-users and Clients to respond to uncertainty.

This document is pre-draft, and MAY be submitted as a draft RFC at some stage. While in pre-draft stage, this document is in kramdown-rfc format for easier editing.

--- middle

# Introduction

Email gateway servers commonly use filtering techniques, to reduce the number of threats (phishing, malware, spam) that End-users see in their mailboxes.

However, there are often times when the filtering technology is not able to make a concrete judgement on wether an email should be blocked, quarantined, or delivered to the End-user. In these cases, the messages are often delivered to the End-user, with a warning message, asking them to make a judgement call.

This includes:

  - messages that have a similar From: display name as a person within the organisation, which is common in whaling attacks
  - messages that include a link to legitimate domains, which often host phishing pages or malware (such as survey sites, document hosting services, and CDNs)
  - messages that have attachments, which cannot be scanned for malware (such as encrypted archives)

The current recommended practice is to add these warning messages to the message HTML body. These HTML-based warnings are probematic, because:

  - editing the message body changes the DKIM body hash, invalidating the DKIM signature, making it difficult for Servers to validate messages (such as messages that are automatically forwarded, or scanned through multiple filtering steps)
  - because the format of these messages are not standardised, email clients are not able to provide further technical controls to mitigate potential threats
  - these messages are almost exclusively in English, making it potentially difficult for End-users who prefer a different language to understand the context of the warning
  - these warnings can interfere with, or be removed by, automated mail processing and response systems, such as ticket management systems
  - users see these messages often, and therefore become accustomed to disregarding these warnings
  - these HTML warnings are often crudely inserted into the message and do not respect the overall HTML message structure, and can corrupt or garble the messages
  - these messages remain in the message body when End-users reply, and therefore can appear in replies outside the organisation, leading to confusion by users

This standard defines a new email Header Field as described in {{RFC2822}}, **Client-Email-Security**, that can be used by Clients to display a rich warning message to an End-user, and MAY impose additional security controls on messages.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

End-user means a person who reads or sends email.

Clients means a piece of software regularly used by an End-user to send and receive email, such as a desktop email client, mobile email client, webmail, ticket management system, etc.

Servers means email Gateways, Mailbox servers, or other appliances that process email messages at the SMTP level

# Implementation

After scanning a message, email Servers MAY insert a **Client-Email-Security** header field, to indicate that this message may contain a specific type of threat.

If present, Clients SHOULD use the Client-Email-Security header to display a warning message to the End-user, indicating that the email may contain a threat. Clients MAY use the presence of a header, and the confidence indicated in the header, to:

  - prevent certain risky actions, such as clicking links, downloading attachments, or replying to the message, without positive confirmation by the End-user that they understand the risk

Clients SHOULD localise messages to End-users in their preferred language.

Clients SHOULD provide configuration options for End-users, to control if additional security controls are applied based on the threat and confidence markings.

If multiple threats are detected, the Server SHOULD select the highest confidence threat. Multiple warning messages should not be displayed to an End-user, as this may cause further confusion.

## Header Signature

It is common practice for an organisation to have seperate services for mail gateway filtering (i.e., the MX record), and mailbox storage/delivery (i.e., the Client's configured mail server).

This presents a challenge to mailbox/delivery services, who need to ensure that messages displayed, and in particular the free-text m= field, is accurate and comes from a source explicitly trusted by the End-user's organisation. 

Following the convention set by DKIM, we use a signature of the Client-Email-Security header, which can be validated by the mailbox Server.

Servers MUST validate the Client-Email-Security header, and MUST remove any Client-Email-Security header which is not signed, has an invalid signature, or has a signature from an untrusted source.

Clients MAY validate the Client-Email-Security header, and SHOULD disregard any Client-Email-Security header which is not signed, or have an invalid signature.

## Tag=Value list

Client-Email-Security uses a simple "tag=value" syntax, to allow for
easy implementation in Clients, and future extensibility.

Values are a series of strings containing either plain text, "base64"
text (as defined in [RFC2045], Section 6.8), "qp-section" (ibid,
Section 6.7), or "dkim-quoted-printable" (as defined in
Section 2.11).  The name of the tag will determine the encoding of
each value.  Unencoded semicolon (";") characters MUST NOT occur in
the tag value, since that separates tag-specs.

    INFORMATIVE IMPLEMENTATION NOTE: Although the "plain text" defined
    below (as "tag-value") only includes 7-bit characters, an
    implementation that wished to anticipate future standards would be
    advised not to preclude the use of UTF-8-encoded ([RFC3629]) text
    in tag=value lists.

Formally, the ABNF syntax rules are as follows:

tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
tag-name  =  ALPHA *ALNUMPUNC
tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
                    ; Prohibits WSP and FWS at beginning and end
tval      =  1*VALCHAR
VALCHAR   =  %x21-3A / %x3C-7E
                    ; EXCLAMATION to TILDE except SEMICOLON
ALNUMPUNC =  ALPHA / DIGIT / "_"

Note that WSP is allowed anywhere around tags.  In particular, any
WSP after the "=" and any WSP before the terminating ";" is not part
of the value; however, WSP inside the value is significant.

Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
processed as case sensitive unless the specific tag description of
semantics specifies case insensitivity.

Tags with duplicate names MUST NOT occur within a single tag-list; if
a tag name does occur more than once, the entire tag-list is invalid.

Whitespace within a value MUST be retained unless explicitly excluded
by the specific tag description.

Tag=value pairs that represent the default value MAY be included to
aid legibility.

Unrecognized tags MUST be ignored.

Tags that have an empty value are not the same as omitted tags.  An
omitted tag is treated as having the default value; a tag with an
empty value explicitly designates the empty string as the value.

##  Signing and Verification Algorithms

Client-Email-Security supports multiple digital signature algorithms.
One algorithm is defined by this specification at this time: rsa-sha256.
Signers MUST implement and sign using rsa-sha256.

## The rsa-sha256 Signing Algorithm

The rsa-sha256 Signing Algorithm computes a message hash as described
in Section 3.7 using SHA-256 [FIPS-180-3-2008] as the hash-alg.  That
hash is then signed by the Signer using the RSA algorithm (defined in
PKCS#1 version 1.5 [RFC3447]) as the crypt-alg and the Signer's
private key.  The hash MUST NOT be truncated or converted into any
form other than the native binary form before being signed.  The
signing algorithm SHOULD use a public exponent of 65537.

## Key Sizes

Selecting appropriate key sizes is a trade-off between cost,
performance, and risk.  Since short RSA keys more easily succumb to
off-line attacks, Signers MUST use RSA keys of at least 1024 bits for
long-lived keys.  Verifiers MUST be able to validate signatures with
keys ranging from 512 bits to 2048 bits, and they MAY be able to
validate signatures with larger keys.  Verifier policies may use the
length of the signing key as one metric for determining whether a
signature is acceptable.

Factors that should influence the key size choice include the
following:

o  The practical constraint that large (e.g., 4096-bit) keys might
    not fit within a 512-byte DNS UDP response packet

o  The security constraint that keys smaller than 1024 bits are
    subject to off-line attacks

o  Larger keys impose higher CPU costs to verify and sign email

o  Keys can be replaced on a regular basis; thus, their lifetime can
    be relatively short

o  The security goals of this specification are modest compared to
    typical goals of other systems that employ digital signatures

See [RFC3766] for further discussion on selecting key sizes.

## Other Algorithms

Other algorithms MAY be defined in the future.  Verifiers MUST ignore
any signatures using algorithms that they do not implement.

## Selectors

To support multiple concurrent public keys per signing domain, the
key namespace is subdivided using "selectors".  For example,
selectors might indicate the names of office locations (e.g.,
"sanfrancisco", "coolumbeach", and "reykjavik"), the signing date
(e.g., "january2005", "february2005", etc.), or even an individual
user.

# Header Field Specification

## Tag Specifications

d=
    <str>
    The domain name of the organisation that has provided the filtering service.

s=
    <str>
    The selector for the message signature.

t=
    This field indicates the type of threat that was detected. Values for this field are:

    impersonated_user
        This threat indicates that a user who 
    impersonated_domain
    encrypted_attachment
    phishing
    malware
    spam
    new_user
    new_domain

Note: a threat category for "external" does not exist by design. Stamping every message with a warning that the email originated outside the End-user's organisation degrades the overall effectiveness of the warnings, and End-users become accustomed to disrecarding these warnings.

c=
    This field indicates the confidence of the threat detected. Values for this field are:

    high
        "high" confidence SHOULD NOT normally be used - if a filter detects a threat with high confidence, it would usually be blocked or quarantined. "high" SHOULD be used in cases where a threat would have been blocked, but an email delivery rule (i.e., a bypass rule for a specific domain) prevented the threat from being blocked or quarantined.
    medium
    low

m=
    <str>
    An optional free-text field providing additional information to the End-user about why the threat was detected.

bh=

sig=

## Other uses

Servers MUST NOT insert the Client-Email-Security header on a message, except when a specific security threat is detected in the email. Using the Client-Email-Security header for advertising, to advise the user of generic security issues (such as "your password is about to expire"), or other organisation-wide messages, is strictly prohibited.

# IANA Considerations

Client-Email-Security is a new Header Field Name that needs to be registered with IANA.

## Client-Email-Security Tag Specifications

| TYPE | REFERENCE            |
|------|----------------------|
| bh   | (this specification) |

# Other work

https://docs.microsoft.com/microsoft-365/security/office-365-security/anti-spam-message-headers

