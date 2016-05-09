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

Here's what some boxing and signing keys look like serialized to JSON (think key stores, PKCS#12, and PKCS#8):

	{
	  "Version": "Buttermilk Tweet Pepper Keys 1.0",
	  "Contents": {
	    "11UO37mprBYTu687QaVFha-X": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Boxing",
	      "CreatedOn": "2016-05-08T17:14:47.745+10:00",
	      "P": "uqTj9dqubWgnkID-XWvrH-4enInYxJBBLwZw2B5zvjU=",
	      "X": "AABAAAAAAEAAAAABbTOjDs_BebL7EBQVKfJ-bPlDtBEGqjOLx60oo6WK1Lij2bohxLgU9AHMzY-YUVz66yg_QYEN54SCH7FPJhHcna8SZKPpK5iIv_i_X9rB8ku7atzNMGWehg=="
	    },
	    "jHaarE7kJgHj0VuRzpl7Y-X": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Signing",
	      "CreatedOn": "2016-05-08T17:14:47.775+10:00",
	      "P": "BW67LiJY1vqZhSny-iPHLok9WMgJJlKQ7M3ggtvBKgo=",
	      "X": "AABAAAAAAEAAAAABc2ujPzpivoQygjc-PDI3FlV1QqyppCIOi5tFAbCIvXuBMorAC_ZU5PPexPiuOhGm9LXiAZvbXlGZ_mrmH6yNs0yCuIvPQA69TPDMCmOwNyFUHaDhiD67_H_xgkwBPxbCGzOdWfj6XNXNhfNYXHYYaKo2_PwPH-Pt"
	    }
	  }
	}

This protection format is intended to remain local to the secret keeper (i.e., is not for key publication).

Here's what an item intended for publication might look like. This is for, e.g., a web service call. It contains a verifiable
signature over the contents which includes public keys, an info affirmation, and contact info. Think replacement for X-509.

	{
	  "Version": "Buttermilk Tweet Pepper 1.0",
	  "KMUHandle": "dSruIH9reptjSMUggsEjv-T",
	  "AdminEmail": "dave@cryptoregistry.com",
	  "Contents": {
	    "MjXndz59kq7Bow1wZwCbP-C": {
	      "ContactType": "Person",
	      "GivenName.0": "David",
	      "FamilyName.0": "Smith",
	      "Email.0": "dave@cryptoregistry.com",
	      "MobilePhone.0": "+61449957431",
	      "TwitterHandle": "Chinese_Knees",
	      "Country": "AU"
	    },
	    "6OoEjbI344AGWb9BXWV3kD-D": {
	      "Copyright": "Copyright 2016 by David R. Smith. All Rights Reserved",
	      "TermsOfServiceAgreement": "I agree to cryptoregistry.com's Terms of Service",
	      "InfoAffirmation": "I affirm the information I have entered in this file is valid and correct."
	    },
	    "11UO37mprBYTu687QaVFha-P": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Boxing",
	      "CreatedOn": "2016-05-08T17:14:47.745+10:00",
	      "P": "uqTj9dqubWgnkID-XWvrH-4enInYxJBBLwZw2B5zvjU="
	    },
	    "jHaarE7kJgHj0VuRzpl7Y-P": {
	      "KeyAlgorithm": "TweetNaCl",
	      "KeyUsage": "Signing",
	      "CreatedOn": "2016-05-08T17:14:47.775+10:00",
	      "P": "BW67LiJY1vqZhSny-iPHLok9WMgJJlKQ7M3ggtvBKgo="
	    },
	    "3Sxd7BxmBESuxvjcTRhHLI-S": {
	      "CreatedOn": "2016-05-08T17:29:45.439+10:00",
	      "DigestAlgorithm": "CubeHash-256",
	      "SignedWith": "jHaarE7kJgHj0VuRzpl7Y",
	      "SignedBy": "Chinese_Knees",
	      "s": "D47bu_6PSu3mSNYhVQfbVv4IfFkRQ1okBfh3fAA5KsHDiEm6i5OQo_VK-B6jf8yL-_3BnkssJFsUDtrr9mK9A5OdBiaL5tGmTwycmxnXQTtbY0atOjzMcAFtmxXTGHzm",
	      "DataRefs": "3Sxd7BxmBESuxvjcTRhHLI-S:CreatedOn, .SignedBy, .SignedWith, MjXndz59kq7Bow1wZwCbP-C:ContactType, .GivenName.0, .FamilyName.0, .Email.0, .MobilePhone.0, .TwitterHandle, .Country, 6OoEjbI344AGWb9BXWV3kD-D:Copyright, .TermsOfServiceAgreement, .InfoAffirmation, 11UO37mprBYTu687QaVFha-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P, jHaarE7kJgHj0VuRzpl7Y-P:KeyAlgorithm, .KeyUsage, .CreatedOn, .P"
	    }
	  }
	}



## API Quickstart

The TweetSalt core class. This has been reworked to be more usable: thread-safe, object-oriented, and also 
formatted for my Java programmer eyes. A lot of people might be interested just in this class, so here is the
direct link: 

https://github.com/buttermilk-crypto/tweetnacl-java/blob/master/src/main/java/com/cryptoregistry/tweet/salt/TweetNaCl.java

The methods are still named as in the project we forked from.

But I encourage you to look a bit further: TweetPepper provides higher level API with a class wrapping the "salt" core and augments it with methods for other things you probably want to do with cryptography anyway.

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
	KMUOutAdapter kmuWriter = new KMUOutAdapter(confidential);
	StringWriter keys = new StringWriter();
	kmuWriter.emitKeys(keys);
 
Example output is two blocks of type "X" as seen above on this page.

## Key Classes

The implementation contains a nice class hierarchy for keys to give structure to the raw DJB keys. The chief benefit is strong typing to represent the keys which otherwise would be merely byte arrays, as well as a place to hang metadata. 

All keys contain at least some metadata, which currently is the date and time of key generation, the block type, and the key usage (boxing, signing, or secretbox).
 
Have a browse of https://github.com/buttermilk-crypto/tweetnacl-java/tree/master/src/main/java/com/cryptoregistry/tweet/pepper/key

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

The map part of the block is intentionally limited to String key-value pairs. Data values are typically base64url
encoded if they represent binary data. 

Blocks have types. The type is essentially a descriptor for what we expect to find in the block, for example an -S
type block is a signature block and is expected to have signature-related data and nothing else. A -C type block
contains contact information and nothing else. And so on. The com.cryptoregistry.tweet.pepper.BlockType enum defines
these types.

The block type is appended at the end of the name of the block using a dash and a capital letter, e.g., <UUID>-D.

Here is a block showing contact information:

	{
	"MjXndz59kq7Bow1wZwCbP-C": {
	      "ContactType": "Person",
	      "GivenName.0": "David",
	      "FamilyName.0": "Smith",
	      "Email.0": "dave@cryptoregistry.com",
	      "MobilePhone.0": "+61449957431",
	      "TwitterHandle": "Chinese_Knees",
	      "Country": "AU"
	    }
	}

In JSON terminology it is an object with one key and a value which is a nested object of String keys and values. Notice that the inner keys take generally a CamelCase form, and if the key is potentially multivariate like the GivenName, then it is
appended with a zero-based integer to show there might be more than one. Also notice the phone number is in international format including the plus sign and country code.  

That's basically all there is to say here about Blocks in order to start using them.

KMUs or Key Material Units are container data structures which hold blocks. KMUs are represented by JSON objects with the following keys:

  + Version
  + KMUHandle - a UUID with appended -T
  + AdminEmail - an email address which is supposed to be more or less anonymous, like admin@mywebsite.com
  + Contents - an object containing an arbitrary number of blocks.

The KMU class has some methods to assist with basic housekeeping, such as adding blocks, protecting and unprotecting
private key bytes within key blocks, and also finding keys easily.
 
That's basically all there is to know about KMUs in order to use them. Note that for internal use (when the KMU is 
never intended to represent published data) then the KMUHandle and AdminEmail are sometimes not required. The KMUHandle is intended 
to work as a transaction token and the email an automated way to contact someone about that transaction. 
 
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
	KMUOutAdapter k = new KMUOutAdapter(container);
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
    		
## The Digest Package

DJB has an interesting digest algorithm called CubeHash: https://en.wikipedia.org/wiki/CubeHash. I'm using
the java implementation from the SAPHIR project. This API works in a slightly different way than Bouncycastle's
Digest classes:

	Digest digest = new CubeHash256(); 
	digest.update(str.getBytes(StandardCharsets.UTF_8));
	byte [] hash = digest.digest();


## Internal JSON package

Yes, I'm using an internal JSON package taken from a project by EclipseSource: https://github.com/ralfstx/minimal-json/tree/master/com.eclipsesource.json/src

Normally I would just use Jackson, but I'm trying to economize and Jackson comes at the cost of three jar dependencies,
with a lot of functionality I don't need here. The EclipseSource code is a mere 15 classes, does everything
required so far, and won't collide with whatever else you are doing.


## UUIDs and Identifiers

The explicit intention is that a block is universally distinct from any other and can be recalled from
a database or storage system, such as a registry. To achieve this we use a UUID.

More recently I looked into using a more compact encoding. The [BijectiveEncoder class](https://github.com/buttermilk-crypto/tweetnacl-java/blob/master/src/main/java/com/cryptoregistry/tweet/url/BijectiveEncoder.java) shrinks the 128 bit UUID value into a 22 byte String. For example:

	{
	  "a4BdeTMcoVJC2bbwm3hhB-E": {
	    "S": "76t5L0aodFhNtvELHcBPAI",
	    "P": "1GihEoZwtM7Bag9zfPypG8",
	    "Nonce.0": "-J5q78JdRPwFLeoVFaebBSPkqD86wCUn",
	    "Data.0": "aqc5jLgnCeCRM044lk5UrzGl0-HTD6-APE11wZVBh1tgJOl1uLSZyeUhHQ=="
	  }
	}  

S and P are both 128 bit UUIDs to keys elsewhere, and "a4BdeTMcoVJC2bbwm3hhB-E" is the unique identifier for this block. 

## Encryption schemes

There are several different informal schemes available for different use-cases:

  + Use Secret Box. This is a simple approach for local use.
  + Use SCrypt + Secret Box. This is the right approach if the key is to be based on a password.
  + Use authenticated encryption based on the crypto_box function. This is for Diffie-Hellman type situations.
  + Use authenticated encryption+key encapsulation through a crypto_box/Salsa20 combination.
  
The SCrypt implementation is one of the few jar dependencies as TweetNaCl does not contain a KDF. I could have opted for the bouncycastle implementation but I have chosen to use the one from com.lambdaworks instead: https://github.com/wg/scrypt

Here's a direct example:

	TweetNaCl salt = new TweetNaCl();
		
	// key derivation input
	String passwd = "password1";
		
	byte[] scryptsalt = new byte[16];
     SecureRandom.getInstanceStrong().nextBytes(scryptsalt);	
      
    //uses about 60Gb of RAM, takes ~ 15 sec to compute on my system																
    byte[] derived = SCrypt.scrypt(passwd.getBytes(StandardCharsets.UTF_8), scryptsalt, 16384, 256, 1, 32); 
		

This is combined with Secret Box to make a viable confidentiality function which is simple to use:

	TweetPepper tp = new TweetPepper();
	
	// our confidential bytes
	byte [] confidential = ...;
	
	String passwd = "password1";
	
	// use defaults for the SCrypt params
	PBEParams params = tp.createPBEParams();
		
	PBE pbe = new PBE(params);
	String protectedStr = pbe.protect(passwd.toCharArray(), confidential);
		
	// later
	byte [] recovered = pbe.unprotect(passwd.toCharArray(), protectedStr);

Using TweetPepper to create a block containing the contents of an encryption is very simple:

	TweetPepper tp = new TweetPepper();
	BoxingKeyContents mine = tp.generateBoxingKeys();
	BoxingKeyContents theirs = tp.generateBoxingKeys();
	
	String msg = "Hello Tweet Salt Encryption";
		
	Block block = tp.encrypt(theirs, mine, msg);
	System.err.println(Block.toJSON(block));
		
	String result = tp.decrypt(theirs, mine, block);

The output of the toJSON() utility method looks something like this:

	{
	  "6aac4f67-97ad-4629-8c96-43b8203b1a2c-E": {
	    "S": "c47ed70f-8c65-4065-bffc-8d8c1f095978",
	    "P": "2cec8469-fbb0-4b5a-afeb-94e122037224",
	    "Nonce.0": "4jOiukdSO4LjhcHIHIpmjfWAIoeP2Pne",
	    "Data.0": "oCnPl9N2u4GStWTnscOHrkzxwl1ZUYILVn32PsgiyjJF4iOMzLzXY9jZ3Q=="
	  }
	}

S and P are the names of the blocks which provide the keys required to decrypt. 


		



TBC




