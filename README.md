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

The current recommended practice is to add these warning messages to the message HTML. These HTML-based warnings are probematic, because:

  - editing the message body canges the DKIM hash, invalidating the DKIM signature, making it difficult for Servers to validate messages
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

# Implementation Details



## Tag Specifications

d=
    <str>
    The domain name of the organisation that 

s=

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

Clients SHOULD localise messages to End-users in their preferred language.

Clients SHOULD provide configuration options for End-users, to control additional security controls based on the threat and confidence markings.

## Signatures & Trusted Source list

It is common practice for organisations to use seperate services for email gateway/filtering, and email mailboxes/delivery.

This presents a challenge to mailbox/delivery services, who need to ensure that messages displayed, and in particular the free-text m= field, is accurate and comes from a source explicitly trusted by the End-user's organisation. 

Following the convention set by DKIM, 

Clients MAY validate the Client-Email-Security header, and SHOULD disregard any Client-Email-Security header which is not signed, or have an invalid signature.

Servers MUST validate the Client-Email-Security header, and MUST reject any Client-Email-Security header which is not signed, has an invalid signature, or has a signature from an untrusted source.

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

