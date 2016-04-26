# buttermilk tweetPepper

This project was originally forked from https://github.com/ianopolous/tweetnacl-java/ which provided
the nucleus for the rest of the code. Because that fork was GPL'd I cannot include it in buttermilk.

See https://tweetnacl.cr.yp.to/ and https://nacl.cr.yp.to/ for details about "salt".

Bernstein et. al. present the big ideas here: https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf.

So, they can have the big ideas, I'm happy with that. I am working on a small idea, which is that a 
crypto library is not much use without a PKI to support it. 

tweetPepper provides some support for things like key formats, protecting keys, and also has some ideas
about how to use those in the context of twitter. 

Here's what some boxing and signing keys look like serialized to JSON (would replace key stores, PKCS#12 and PKCS#8):

	{
	  "Version": "Buttermilk Tweet Pepper Keys 1.0",
	  "Contents": {
	    "f8dff898-0e78-466b-90d7-ef125aab1d6d-X": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Boxing",
	      "CreatedOn": "2016-04-26T07:49:38.179+10:00",
	      "P": "qxaCCEah63oAOA9fQ1JI5Xi0lQtosv7ujzxpBqA8vVc=",
	      "X": "AABAAAAAAQAAAAAB6Bvv_9iQF5cS_TDNsoX4gvv_yLTMcSGqM1URAQafvTEdzt3huhw90AIbe2d7GrDRIMXuCX0KWMUAGy5UyMVnfzYl3Y37gqz7qAsEbz8nf8ucgbBDIoRO4Q=="
	    },
	    "74cd46ce-cab9-403c-b3f6-61db1af3b518-X": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Signing",
	      "CreatedOn": "2016-04-26T07:49:38.211+10:00",
	      "P": "EY60jCbMaCjGZcbAep7v9c_siH7IObPqPfk-1dJ1CNo=",
	      "X": "AABAAAAAAQAAAAABi8uoI5WB3vqzyqWaxtb29Gk90Il2Ho6x2lUkH3JvVlHGkP8_IVzKTlgg93pDE1FqUX34l2wwSzxlxhccp7NEpfq8T98TeDaBeUVibClcF3eoCTZpnxXIubh1_Cgl9l-t6_ChjoqA-NDJuvLXIXRvF1cEzIV3WUvV"
	    }
	  }
	}

The private key is encrypted using Secret Box, but we generate that key using SCrypt to get a password-based store.
SCrypt is implemented using http://mvnrepository.com/artifact/com.lambdaworks/scrypt/1.4.0. 

This protection format is intended to remain local to the secret keeper (i.e., is not for key publication).

Here's what a transactional block looks like. This is input for, e.g., a web service call. It contains a verifiable
signature over the contents which includes public keys, an info affirmation, and contact info. This is intended to
replace X-509.

	{
	  "Version": "Buttermilk Tweet Pepper 1.0",
	  "KMUHandle": "2f0cc8ff-97cc-4e67-9e6f-b5ebbc9fee07-T",
	  "AdminEmail": "dave@cryptoregistry.com",
	  "Contents": {
	    "85629ad5-9a03-49fd-bc8f-2900a3bdb55a-C": {
	      "ContactType": "Person",
	      "GivenName.0": "David",
	      "FamilyName.0": "Smith",
	      "Email.0": "dave@cryptoregistry.com",
	      "MobilePhone.0": "+61449957431",
	      "TwitterHandle": "Chinese_Knees",
	      "Country": "AU"
	    },
	    "dd000e9a-c2d1-4f97-b641-cf3baaafbf84-D": {
	      "Copyright": "Copyright 2016 by David R. Smith. All Rights Reserved",
	      "TermsOfServiceAgreement": "I agree to cryptoregistry.com's Terms of Service",
	      "InfoAffirmation": "I affirm the information I have entered in this file is valid and correct."
	    },
	    "f8dff898-0e78-466b-90d7-ef125aab1d6d-P": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Boxing",
	      "CreatedOn": "2016-04-26T07:49:38.179+10:00",
	      "P": "qxaCCEah63oAOA9fQ1JI5Xi0lQtosv7ujzxpBqA8vVc="
	    },
	    "74cd46ce-cab9-403c-b3f6-61db1af3b518-P": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Signing",
	      "CreatedOn": "2016-04-26T07:49:38.211+10:00",
	      "P": "EY60jCbMaCjGZcbAep7v9c_siH7IObPqPfk-1dJ1CNo="
	    },
	    "3294bf7a-6aad-4dd1-9c5f-14274d11f803-S": {
	      "CreatedOn": "2016-04-26T11:33:05.177+10:00",
	      "DigestAlgorithm": "CubeHash-256",
	      "SignedWith": "74cd46ce-cab9-403c-b3f6-61db1af3b518",
	      "SignedBy": "Chinese_Knees",
	      "s": "TyTp-f-g5EF7CBXTw6gBxzqfY--8QcE_8nzqzPTjV2-L-TpXSAJ_0J9WVf3xbK2d0HdDjzQVXXrdfdrNGjG5AOuMSPb5AZ6BMOu9LKATrZRVBvoadrMYUTxNoa5zaady",
	      "DataRefs": "85629ad5-9a03-49fd-bc8f-2900a3bdb55a-C:ContactType, .GivenName.0, .FamilyName.0, .Email.0, .MobilePhone.0, .TwitterHandle, .Country, dd000e9a-c2d1-4f97-b641-cf3baaafbf84-D:Copyright, .TermsOfServiceAgreement, .InfoAffirmation, f8dff898-0e78-466b-90d7-ef125aab1d6d-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P, 74cd46ce-cab9-403c-b3f6-61db1af3b518-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P"
	    }
	  }
	}


More details to follow as the coding continues.

 




