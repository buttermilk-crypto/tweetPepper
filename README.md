# buttermilk tweetPepper

tweetPepper provides some support for things like key formats, protecting keys, and also has some ideas
about how to distribute keys via contemporary techniques like social media. 

This project was originally forked from https://github.com/ianopolous/tweetnacl-java/ which provided
the nucleus for the rest of the code. Because that fork was GPL'd I cannot include it in buttermilk.

See https://tweetnacl.cr.yp.to/ and https://nacl.cr.yp.to/ for details about "salt".

Bernstein et. al. present the big ideas here: https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf.

So, they can have the big ideas, I'm happy with that. I am working on a small idea, which is that a 
crypto library is not much use without a PKI to support it. 

## Motivating the idea

Here's what some boxing and signing keys look like serialized to JSON (think key stores, PKCS#12 and PKCS#8):

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

This protection format is intended to remain local to the secret keeper (i.e., is not for key publication).

Here's what an item intended for publication might look like. This is for, e.g., a web service call. It contains a verifiable
signature over the contents which includes public keys, an info affirmation, and contact info. Think replacement for X-509.

	{
	  "Version": "Buttermilk Tweet Pepper 1.0",
	  "KMUHandle": "bc8ecc13-71b2-4c70-99d7-188c1a07453b-T",
	  "AdminEmail": "dave@cryptoregistry.com",
	  "Contents": {
	    "8f3d6826-7bd5-4a1a-976c-3a1fbe6e6a3d-C": {
	      "ContactType": "Person",
	      "GivenName.0": "David",
	      "FamilyName.0": "Smith",
	      "Email.0": "dave@cryptoregistry.com",
	      "MobilePhone.0": "+61449957431",
	      "TwitterHandle": "Chinese_Knees",
	      "Country": "AU"
	    },
	    "869b15cb-91a8-482f-87c5-bed368d093cd-D": {
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
	    "8955516b-8368-49c3-ba93-627faab4fdae-S": {
	      "CreatedOn": "2016-05-05T10:32:10.706+10:00",
	      "DigestAlgorithm": "CubeHash-256",
	      "SignedWith": "74cd46ce-cab9-403c-b3f6-61db1af3b518",
	      "SignedBy": "Chinese_Knees",
	      "s": "5SuJf1ttx2W0pSwHeLlaAiV98MZ9IrVIvme-ZX72dHzr1orn7sbvxbsAiCeg7WxFPQobSMAHMYkMI4cVfEWiA7dKsZs_Eivyil4Lr-VPOHSdJV3XVaI_aAmbyxTAJJSn",
	      "DataRefs": "8955516b-8368-49c3-ba93-627faab4fdae-S:CreatedOn, .SignedBy, .SignedWith, 8f3d6826-7bd5-4a1a-976c-3a1fbe6e6a3d-C:ContactType, .GivenName.0, .FamilyName.0, .Email.0, .MobilePhone.0, .TwitterHandle, .Country, 869b15cb-91a8-482f-87c5-bed368d093cd-D:Copyright, .TermsOfServiceAgreement, .InfoAffirmation, f8dff898-0e78-466b-90d7-ef125aab1d6d-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P, 74cd46ce-cab9-403c-b3f6-61db1af3b518-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P"
	    }
	  }
	}


## API Quickstart

The TweetSalt core class. This has been reworked to be more usable: thread-safe, object-oriented, and also 
formatted for my Java programmer eyes:

https://github.com/buttermilk-crypto/tweetnacl-java/blob/master/src/main/java/com/cryptoregistry/tweet/salt/TweetNaCl.java

The methods are still named as in the project we forked from.

TweetPepper takes this a step further with a class wrapping the core API and augments it with methods for other
things you probably want to do with cryptography.

Use: 

	// 1.0 key generation, nice to have boxing and signing keys in a set
	TweetPepper tp = new TweetPepper();
	BoxingKeyContents key0 = tp.generateBoxingKeys();
	SigningKeyContents key1 = tp.generateSigningKeys();
	
	// 1.1 a KMU or KeyMaterialsUnit is a container for blocks. 
	KMU confidential = new KMU("dave@cryptoregistry.com");
	
	// 1.2 convert the keys into block format and add to the KMU.
	confidential.addBlock(key0.toBlock());
	confidential.addBlock(key1.toBlock());
	
	// 1.3 we'll encrypt the keys using SCrypt for the key derivation and Secret Box for the encryption
	char [] pass = {'p','a','s','s'};
	confidential.protectKeyBlocks(pass);
	
	// 1.4 write out the keys to a StringWriter
	KMUWriter kmuWriter = new KMUWriter(confidential);
	StringWriter keys = new StringWriter();
	kmuWriter.emitKeys(keys);
 
Example output is two blocks of type "X" as seen above on this page.

## Key Classes

The implementation contains a nice class hierarchy for keys. The chief benefit is strong typing to
represent the keys which otherwise would be merely byte arrays. 

All keys contain some metadata, which currently is defined as the date and time of creation, the Block type, and the key usage (boxing, signing, or secretbox).
 

## Blocks and KMUs

PKCS#12 has been described as "a transfer syntax for personal identity information, including private keys, certificates, miscellaneous secrets, and extensions". In my work on identifying a replacement for this type of general construct, 
I find JSON provides the best contemporary encoding. 

Blocks and KMUs (or Key Material Units) are map-like data structures which have simple JSON representations. They
are intended to replace the complexity of the security objects built on ASN.1 with something more amenable to the
project of ubiquitous cryptography.  

A Block is essentially a named map. I sometimes use the terminology "distinguished map." The name is intended 
to be unique across the use domain of the data, e.g., if the domain is the internet, the name should be unique 
across all of the internet. The best way I have found to achieve this is with a UUID. UUIDs are 128 bit data 
structures, they have a standard textual representation, and are easy to process in almost any programming language. 

The map part of the block is intentionally limited to String key-value pairs.  

Blocks have types. The type is essentially a descriptor for what we expect to find in the block, for example an -S
type block is a signature block and is expected to have signature-related data and nothing else. A -C type block
contains contact information and nothing else. And so on. The com.cryptoregistry.tweet.pepper.BlockType enum defines
these types. 

The block type is appended at the end of the name of the block using a dash and a capital letter, e.g., <UUID>-D.

Here is a block showing contact information:

	{
	"8f3d6826-7bd5-4a1a-976c-3a1fbe6e6a3d-C": {
		      "ContactType": "Person",
		      "GivenName.0": "David",
		      "GivenName.1": "Richard",
		      "FamilyName.0": "Smith",
		      "Email.0": "dave@cryptoregistry.com",
		      "MobilePhone.0": "+61449957431",
		      "TwitterHandle": "Chinese_Knees",
		      "Country": "AU"
		}
	}

In JSON terminology it is an object with one key - the name - and a value which is a nested object of String keys and values. Notice that the keys take a special form, if the key is potentially multivariate like the GivenName, then it is
appended with a zero-based integer. Also notice the phone number is in international format including the plus sign and
country code.  

That's basically all there is to say here about Blocks.

KMUs or Key Material Units are container data structures which hold blocks. KMUs are represented by JSON objects with the following keys:

  + Version
  + KMUHandle - a UUID with appended -T
  + AdminEmail - an email address which is supposed to be more or less anonymous, like admin@mywebsite.com
  + Contents - an object containing an arbitrary number of blocks.

That's basically all there is to know about KMUs in order to use them. Note that for internal use (when the KMU is 
never intended to represent published data) then the KMUHandle and AdminEmail are sometimes not required. The KMUHandle is intended to work as a transaction token and the email an automated way to contact someone about that transaction. 
 
## Digital Signature Support

The current scheme includes the technique of digitally signing arbitrary blocks and then validating the signature
at some later date. The signature is detached in it's own block, which has been formatted for clarity:

	"8955516b-8368-49c3-ba93-627faab4fdae-S": {
		 "CreatedOn": "2016-05-05T10:32:10.706+10:00",
		 "DigestAlgorithm": "CubeHash-256",
		 "SignedWith": "74cd46ce-cab9-403c-b3f6-61db1af3b518",
		 "SignedBy": "Chinese_Knees",
		 "s": "5SuJf1ttx2W0pSwHeLlaAiV98MZ9Ir...",
		 "DataRefs": "8955516b-8368-49c3-ba93-627faab4fdae-S:CreatedOn, .SignedBy, .SignedWith, 
		    8f3d6826-7bd5-4a1a-976c-3a1fbe6e6a3d-C:ContactType, .GivenName.0, .FamilyName.0, .Email.0, 
		    869b15cb-91a8-482f-87c5-bed368d093cd-D:Copyright, .TermsOfServiceAgreement, .InfoAffirmation, 
		    f8dff898-0e78-466b-90d7-ef125aab1d6d-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P, 
		    74cd46ce-cab9-403c-b3f6-61db1af3b518-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P"
	}
	
The block is of type -S, for signature.

The CreatedOn date/time is encoded in full ISO 8601 format. 

The DigestAlgorithm is currently one of CubeHash-224, CubeHash-256, CubeHash-384, or CubeHash-512.

The SignedWith field indicates the signing key's block name. Note that it does not include the block type. 

The SignedBy field is in this implementation the Twitter handle of the secret keeper for the signing key. 

The "s" field contains the signature bytes themselves in Base64url encoded format.

The DataRefs field is a list of the signed items in digest order. The items are in a distinguished form: the
full UUID and block type of the block the item is in, plus the key for the value. However, if the next item
in the list is from the same block, then the item is allowed to take the short form <dot><key>.  

To create a signature block, use an instance of the TweetPepperSigner class. First make some blocks to sign: 

	Block contactInfo = new Block(BlockType.C);
    	 contactInfo.put("GivenName.0","David");
    	 contactInfo.put("FamilyName.0","Smith");

	Block dataBlock = new Block(BlockType.D);
    	  dataBlock.put("Some data","mydata");
    	
	Block pubBoxing = boxingKey.pubBlock();
	Block pubSigning = signingKey.pubBlock();
    	  
Then add these to a KMU to work as a container:

	KMU container = new KMU("dave@cryptoregistry.com");
	container.addBlock(contactInfo)
	.addBlock(dataBlock)
	.addBlock(pubBoxing)
	.addBlock(pubSigning);
	      	  
	TweetPepperSigner signer = new TweetPepperSigner("Chinese_Knees", signingKey);
	signer.addKMUBlocks(container);
	TweetPepperSignature signatureObj = signer.sign();
	
	// add the signature block into the KMU
	container.addBlock(signatureObj.toBlock());
	      	  
	// now print out the whole thing
	KMUWriter k = new KMUWriter(container);
	StringWriter strWriter = new StringWriter();
	container.writeTo(strWriter);
	System.err.println(strWriter.toString());
	      	  
The verifier works like the below. It takes a set of blocks or KMUs as input. The input blocks should include the expected
public signing key in a -P block, and an -S block to validate:

	TweetPepperVerifier verifier = new TweetPepperVerifier();
	verifier.addKMUBlocks(kmu);
	if(!verifier.verify()){
	    // fail
	}
    		
## Encryption schemes

There are several different informal schemes available:

  + Use Secret Box. This is a simple approach for local use.
  + Use SCrypt + Secret Box. This is the right approach if the key is to be based on a password.
  + Use authenticated encryption based on the crypto_box function. This is for Diffie-Hellman type situations.
  + Use authenticated encryption+key encapsulation through crypto_box/Salsa20 combination.
  


TBC




