This repo contains an Asynchronous BFT Consensus based on the HoneyBadger Consensus
---------------------------------------------------------------------------------------------
Developed by Taekion for Hyperledger Sawtooth

What is it for?
---------------

This is a consensus mechanism that 

What does it do?
----------------

Uue this consensus when 

Getting Started
---------------

A application-specific client library needs to implement the following interface:An attempt to be more asynchronous and do bft in consensus for the Hyperledger Sawtooth Blockchain

## Configuration

The configuration is put in a JSON file and contains the secret key share and public key set information.

```
{
  "sec_key_share":[
    9618116941043444446,
    3910152738615756309,
    7294972905033048309,
    5704457943483918691
  ],
  "pkset": {
    "commit": {
      "coeff":[
        [178,56,216,197,27,204,79,229,40,56,147,69,207,103,88,221,69,165,106,173,37,233,124,62,204,172,118,108,194,63,18,8,102,140,252,202,213,177,88,64,112,89,246,95,201,172,185,229],
        [182,170,64,130,170,60,161,161,187,55,59,107,175,219,171,129,174,125,36,148,93,9,123,239,182,104,9,142,44,78,106,147,159,101,166,125,230,169,98,122,190,184,255,25,185,162,37,170]
      ]
    }
  }
}
```

The `genshares` tool can help you generate your config, pass it all of the public key identities of your validators as args:
```
> genshares \
02dfb9b074448ab903cc84ec543f80250fd0b1a43b162f2ce0e92485417ec3e14e \
02ecafa9876c04380a385f61c085ec9f6157ff50d49624c9b45e1819a14ac0e424 \
03c0fea0ed3d65cfd89df54a8158ae7a7d746f1c51aaab4e2b5dcb1e913e8fd7ee \
0280f795a25d24e522704f13742cd27b40bf551f10052bb62100e81b91f20c6427 \
0271b324b68efb2a389dc4193c03138ef5d62971dce9dd5046de3b205ceeaf3812
```

## Running

Three arguments are available:
* __-v__: Verbose output, can be present up to 3 times for more verbosity
* __-C || --connect__: The validator endpoint to connect to
* __-c__: The path to the json config file described above

Example run line:
`abft-consensus -vv --connect tcp://validator:5050 -c /etc/sawtooth/abft.json`
