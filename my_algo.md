data -> either key/password or any other secret text (header.payload.signature)

1. choose random key -> randkey
2. encrypt using random key -> encdata
3. hash the output of step 2 -> hash_encdata
4. xor the random key with the output of step 3 -> xoredkey
5. prefinal transmission -> output of step 2 + output of step 4
6. take crc of prefinal transmission and append & prepend
