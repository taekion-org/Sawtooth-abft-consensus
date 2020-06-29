An attempt to be more asynchronous and do bft in consensus

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

## Running

Three arguments are available:
* __-v__: Verbose output, can be present up to 3 times for more verbosity
* __-C__: The validator endpoint to connect to
* __-c__: The path to the json config file described above