// considering the following key
String key = 'JBSWY3DPEHPK3PXP';

// and the current time (in miliseconds, and as string)
String currentTime =  System.now().getTime()+'';

// Using the algorithm HMAC-SHA1
String algo = 'hmacSha1';

// And returning six digits for the user to confirm
Integer digits = 6;

System.debug(TOTP.generateCodes(key, currentTime, digits, algo));
