// considering the following key
String key = 'Hello world!';

// and the current time (in miliseconds, and as string)
Long currentTime =  System.now().getTime();

// Using the algorithm HMAC-SHA1
String algo = 'hmacSha1';

// And returning six digits for the user to confirm
Integer digits = 6;

System.debug(new TOTP.KeyURI(key, 'renato@totp.demo', 'TOTP, Inc').getURL());

System.debug(TOTP.generateCodes(key, currentTime, digits, algo));
