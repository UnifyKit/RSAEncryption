# RSAEncryption
The RSA encryption algorithm uses two Keys: Private and Public to encrypt and decrypt.


####Scenario A

Suppose Alice wants to send a message to Bob (for his eyes only!). She can encrypt the message using the RSA algorithm with Bob's Public Key, which is not a secret (that's why they call it Public…). Once the message is encrypted, nobody can decrypt it, except the one holding the matching Private Key (that is Bob).

####Scenario B

The reverse is also true: if Alice would encrypt the message using her own Private Key, Bob (and Eve, and everyone who can access this "encrypted" message) can decrypt it using Alice's Public Key. So, if everybody can decrypt it, what's the point in encrypting the message with a Private Key in the first place? Well, there is a point if Bob wants to make sure that the message has been written by Alice and not by someone else (Eve?).


####.NET RSACryptoServiceProvider

The .NET Framework implements the RSA algorithm in the RSACryptoServiceProvider class. The instance of this class lets you create Key pairs, encrypt using a public key, decrypt using a private key (as in the first scenario), sign (sort of the second scenario, but not exactly), and verify the signature.

The Sign method accepts a message (as byte array) and creates a signature for this particular data. In the second scenario, Alice can write a message to Bob, and use this method to get a signature with her own private key. Then, she can send the message to Bob as is (unencrypted) with the signature. To verify the writer ID (Alice), Bob will use the Verify method with Alice's public key as: Verify(aliceMessage, aliceSignature), and he will get "true" if this is the original message written and signed by Alice, or "false" if even one bit has been changed since. This is one useful implementation of private key encryption, but sometimes it's just too complicated. You might want to send just a little message so the receiver can decrypt it and be sure it's from you, without the need to sign and send him both components.
